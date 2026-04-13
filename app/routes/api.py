"""Internal API routes for programmatic access."""

import base64
import logging
import uuid
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, g, Response

from app.models import (
    db, Control, Policy, TestRecord, Evidence, DecisionLogSession,
    DecisionLogEntry, System, Vendor, TeamMember, AuditLog,
)
from app.auth import require_api_key, require_admin

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__)


@api_bp.route("/health")
def health():
    """Health check endpoint.
    ---
    tags:
      - System
    responses:
      200:
        description: Service is healthy and database is reachable
        content:
          application/json:
            schema:
              type: object
              properties:
                status:
                  type: string
                  example: ok
                service:
                  type: string
                  example: trust-portal
                database:
                  type: string
                  example: connected
      503:
        description: Service is degraded (database unreachable)
    """
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify({"status": "ok", "service": "trust-portal", "database": "connected"})
    except Exception:
        logger.warning("Health check: database unreachable")
        return jsonify({"status": "degraded", "service": "trust-portal", "database": "unreachable"}), 503


@api_bp.route("/compliance-score")
@require_api_key
def compliance_score():
    """Return overall and per-category compliance scores.
    ---
    tags:
      - Compliance
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: Compliance scores by category
        content:
          application/json:
            schema:
              type: object
              properties:
                overall_score:
                  type: number
                  example: 75.0
                total_tests:
                  type: integer
                  example: 100
                passed_tests:
                  type: integer
                  example: 75
                categories:
                  type: object
                  additionalProperties:
                    type: object
                    properties:
                      total_tests:
                        type: integer
                      passed_tests:
                        type: integer
                      score:
                        type: number
      401:
        description: Missing or invalid API key
    """
    total_tests = TestRecord.query.count()
    passed_tests = TestRecord.query.filter_by(status="passed").count()
    overall = (passed_tests / total_tests * 100) if total_tests > 0 else 0

    categories = {}
    for category in ["security", "availability", "confidentiality", "privacy", "processing_integrity"]:
        controls = Control.query.filter_by(category=category).all()
        control_ids = [c.id for c in controls]
        if control_ids:
            cat_total = TestRecord.query.filter(TestRecord.control_id.in_(control_ids)).count()
            cat_passed = TestRecord.query.filter(
                TestRecord.control_id.in_(control_ids),
                TestRecord.status == "passed"
            ).count()
        else:
            cat_total = cat_passed = 0
        categories[category] = {
            "total_tests": cat_total,
            "passed_tests": cat_passed,
            "score": round((cat_passed / cat_total * 100), 1) if cat_total > 0 else 0,
        }

    return jsonify({
        "overall_score": round(overall, 1),
        "total_tests": total_tests,
        "passed_tests": passed_tests,
        "categories": categories,
    })


@api_bp.route("/compliance-journey")
@require_api_key
def compliance_journey():
    """Return the current state of the SOC 2 compliance journey across all phases.
    ---
    tags:
      - Compliance
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: Full journey state with phase completion, next actions, and compliance score
      401:
        description: Missing or invalid API key
    """
    from app.services.settings_service import get_portal_settings

    TSC_CATEGORIES = ["security", "availability", "confidentiality", "privacy", "processing_integrity"]

    settings = get_portal_settings()

    # Counts used across phases
    total_controls = Control.query.count()
    total_tests = TestRecord.query.count()
    total_policies = Policy.query.count()
    total_systems = System.query.count()
    total_vendors = Vendor.query.count()
    total_team_members = TeamMember.query.filter_by(is_active=True).count()
    total_evidence = Evidence.query.count()
    total_decision_log_sessions = DecisionLogSession.query.count()

    passed_tests = TestRecord.query.filter_by(status="passed").count()
    approved_policies = Policy.query.filter_by(status="approved").count()

    tests_missing_evidence = TestRecord.query.filter_by(evidence_status="missing").count()
    tests_with_evidence = total_tests - tests_missing_evidence
    evidence_gaps = TestRecord.query.filter(
        TestRecord.evidence_status.in_(["missing", "outdated", "due_soon"])
    ).count()

    # Category coverage
    categories_with_policies = set()
    for p in Policy.query.with_entities(Policy.category).distinct().all():
        if p.category:
            categories_with_policies.add(p.category)

    categories_with_controls = set()
    for c in Control.query.with_entities(Control.category).distinct().all():
        if c.category:
            categories_with_controls.add(c.category)

    # Controls without tests
    controls_with_tests = set()
    for t in TestRecord.query.with_entities(TestRecord.control_id).distinct().all():
        controls_with_tests.add(t.control_id)
    controls_without_tests = total_controls - len(controls_with_tests)

    # Compliance score
    overall_score = round((passed_tests / total_tests * 100), 1) if total_tests > 0 else 0.0

    # Audit log check (lightweight — just check latest entry has hash)
    latest_audit = AuditLog.query.order_by(AuditLog.id.desc()).first()
    audit_log_has_hashes = bool(latest_audit and latest_audit.row_hash)
    audit_log_entries = AuditLog.query.count()

    # Evidence due/outdated
    evidence_due_soon = TestRecord.query.filter_by(evidence_status="due_soon").count()
    evidence_outdated = TestRecord.query.filter_by(evidence_status="outdated").count()

    # Policies due for review
    policies_due_review = 0
    _now_utc = datetime.now(timezone.utc)
    for p in Policy.query.all():
        if hasattr(p, "next_review_at") and p.next_review_at:
            # Normalize naive datetimes from Postgres (timezone-less columns)
            # so they can be compared against the timezone-aware "now".
            nr = p.next_review_at
            if nr.tzinfo is None:
                nr = nr.replace(tzinfo=timezone.utc)
            if nr <= _now_utc:
                policies_due_review += 1

    # --- Phase completion logic ---
    settings_configured = bool(settings.get("company_legal_name"))

    phases = {}

    # Phase 1: Bootstrap
    p1_checks = {
        "portal_healthy": True,
        "settings_configured": settings_configured,
        "team_members_exist": total_team_members > 0,
    }
    p1_complete = all(p1_checks.values())

    # Phase 2: Discovery
    p2_checks = {
        "systems_registered": total_systems > 0,
        "vendors_registered": total_vendors > 0,
        "systems_count": total_systems,
        "vendors_count": total_vendors,
    }
    p2_complete = p2_checks["systems_registered"] and p2_checks["vendors_registered"]

    # Phase 3: Policies
    categories_missing_policies = [c for c in TSC_CATEGORIES if c not in categories_with_policies]
    p3_checks = {
        "policies_exist": total_policies > 0,
        "policies_count": total_policies,
        "policies_approved": approved_policies,
        "policies_draft": total_policies - approved_policies,
        "all_categories_covered": len(categories_missing_policies) == 0 and total_policies >= 5,
        "categories_covered": sorted(categories_with_policies),
        "categories_missing": categories_missing_policies,
    }
    p3_complete = (total_policies >= 5 and approved_policies == total_policies
                   and len(categories_missing_policies) == 0)

    # Phase 4: Controls & Tests
    categories_missing_controls = [c for c in TSC_CATEGORIES if c not in categories_with_controls]
    p4_checks = {
        "controls_exist": total_controls > 0,
        "controls_count": total_controls,
        "tests_exist": total_tests > 0,
        "tests_count": total_tests,
        "controls_without_tests": controls_without_tests,
        "all_categories_have_controls": len(categories_missing_controls) == 0,
        "categories_with_controls": sorted(categories_with_controls),
        "categories_missing_controls": categories_missing_controls,
    }
    p4_complete = (total_controls > 0 and total_tests > 0
                   and controls_without_tests == 0
                   and len(categories_missing_controls) == 0)

    # Phase 5: Evidence Collection
    from app.services.collector_status import get_overview as _get_collector_overview
    collector_overview = _get_collector_overview()
    p5_checks = {
        "total_tests": total_tests,
        "tests_with_evidence": tests_with_evidence,
        "tests_missing_evidence": tests_missing_evidence,
        "evidence_items_count": total_evidence,
        "decision_log_sessions": total_decision_log_sessions,
        "collectors_total": collector_overview.total,
        "collectors_configured": collector_overview.configured,
        "collectors_enabled": collector_overview.enabled,
        "collectors_running_successfully": collector_overview.running_successfully,
    }
    p5_complete = (
        total_tests > 0
        and tests_missing_evidence == 0
        and collector_overview.running_successfully > 0
    )

    # Phase 6: Gap Analysis
    category_scores = {}
    for cat in TSC_CATEGORIES:
        cat_controls = Control.query.filter_by(category=cat).all()
        cat_ids = [c.id for c in cat_controls]
        if cat_ids:
            cat_total = TestRecord.query.filter(TestRecord.control_id.in_(cat_ids)).count()
            cat_passed = TestRecord.query.filter(
                TestRecord.control_id.in_(cat_ids), TestRecord.status == "passed"
            ).count()
            category_scores[cat] = round((cat_passed / cat_total * 100), 1) if cat_total > 0 else 0.0
        else:
            category_scores[cat] = 0.0

    p6_checks = {
        "compliance_score": overall_score,
        "tests_passed": passed_tests,
        "tests_failed": TestRecord.query.filter_by(status="failed").count(),
        "tests_pending": TestRecord.query.filter_by(status="pending").count(),
        "evidence_gaps_count": evidence_gaps,
        "category_scores": category_scores,
    }
    p6_complete = overall_score >= 80.0 and evidence_gaps == 0

    # Phase 7: Audit Prep
    soc2_stage = settings.get("soc2_current_stage", "not_started")
    stage_keys = ["not_started", "policies_established", "collecting_point_in_time",
                  "auditor_engaged", "type_1_completed", "collecting_continuous", "type_2_completed"]
    stage_index = stage_keys.index(soc2_stage) if soc2_stage in stage_keys else 0

    p7_checks = {
        "audit_log_has_hashes": audit_log_has_hashes,
        "audit_log_entries": audit_log_entries,
        "all_policies_approved": approved_policies == total_policies and total_policies > 0,
        "all_evidence_current": evidence_gaps == 0 and total_tests > 0,
        "soc2_stage": soc2_stage,
    }
    p7_complete = (audit_log_has_hashes and p7_checks["all_policies_approved"]
                   and p7_checks["all_evidence_current"] and stage_index >= 3)

    # Phase 8: Ongoing
    p8_checks = {
        "policies_due_for_review": policies_due_review,
        "evidence_due_soon": evidence_due_soon,
        "evidence_outdated": evidence_outdated,
    }

    # Determine status for each phase
    completion = [p1_complete, p2_complete, p3_complete, p4_complete,
                  p5_complete, p6_complete, p7_complete]

    # Current phase = first incomplete, or 8 if all done
    current_phase = 8
    for i, done in enumerate(completion):
        if not done:
            current_phase = i + 1
            break

    phase_data = [
        ("1_bootstrap", p1_checks, p1_complete),
        ("2_discovery", p2_checks, p2_complete),
        ("3_policies", p3_checks, p3_complete),
        ("4_controls_and_tests", p4_checks, p4_complete),
        ("5_evidence_collection", p5_checks, p5_complete),
        ("6_gap_analysis", p6_checks, p6_complete),
        ("7_audit_prep", p7_checks, p7_complete),
        ("8_ongoing", p8_checks, False),
    ]

    for i, (name, checks, complete) in enumerate(phase_data):
        phase_num = i + 1
        if complete:
            status = "completed"
        elif phase_num == current_phase:
            status = "in_progress"
        elif phase_num == 8 and current_phase == 8:
            status = "in_progress"
        else:
            status = "not_started"
        phases[name] = {"status": status, "checks": checks}

    # Generate next_actions
    next_actions = []
    if current_phase == 1:
        if not settings_configured:
            next_actions.append("Configure portal settings with company information (update-settings)")
        if total_team_members == 0:
            next_actions.append("Create at least one team member via the admin UI at /admin/team")
    elif current_phase == 2:
        if total_systems == 0:
            next_actions.append("Register your systems — cloud services, applications, databases (create via /api/systems)")
        if total_vendors == 0:
            next_actions.append("Register your vendors — third-party services that handle data (create via /api/vendors)")
    elif current_phase == 3:
        if total_policies < 5:
            next_actions.append(f"Create SOC 2 policies. Only {total_policies} exist, need at least 5 covering all TSC categories.")
        if categories_missing_policies:
            next_actions.append(f"Missing policy coverage for: {', '.join(categories_missing_policies)}")
        if approved_policies < total_policies:
            next_actions.append(f"{total_policies - approved_policies} policies are not yet approved.")
    elif current_phase == 4:
        if categories_missing_controls:
            next_actions.append(f"Create controls for: {', '.join(categories_missing_controls)}")
        if controls_without_tests > 0:
            next_actions.append(f"{controls_without_tests} controls have no test records. Create tests for all controls.")
        if total_tests == 0:
            next_actions.append("Create test records linked to controls with clear pass/fail criteria.")
    elif current_phase == 5:
        if collector_overview.running_successfully == 0:
            next_actions.append(
                "Configure at least one evidence collector and run it successfully. "
                "Start with the setup wizard at /admin/setup/collectors."
            )
        if tests_missing_evidence > 0:
            next_actions.append(f"{tests_missing_evidence} tests are missing evidence. Run automated collectors and collect manual evidence.")
    elif current_phase == 6:
        if overall_score < 80:
            next_actions.append(f"Compliance score is {overall_score}%. Review and remediate failed tests to reach 80%.")
        if evidence_gaps > 0:
            next_actions.append(f"{evidence_gaps} tests have evidence gaps (missing, outdated, or due soon).")
    elif current_phase == 7:
        if not audit_log_has_hashes:
            next_actions.append("Verify audit log integrity (verify-audit-log).")
        if not p7_checks["all_policies_approved"]:
            next_actions.append("Ensure all policies are approved.")
        if stage_index < 3:
            next_actions.append(f"Update SOC 2 stage (currently: {soc2_stage}). Engage an auditor when ready.")
    elif current_phase == 8:
        if evidence_due_soon > 0:
            next_actions.append(f"{evidence_due_soon} tests have evidence due soon.")
        if evidence_outdated > 0:
            next_actions.append(f"{evidence_outdated} tests have outdated evidence — re-collect.")
        if policies_due_review > 0:
            next_actions.append(f"{policies_due_review} policies are due for review.")
        if not next_actions:
            next_actions.append("Compliance program is healthy. Continue periodic evidence collection and policy reviews.")

    phase_names = {1: "bootstrap", 2: "discovery", 3: "policies", 4: "controls_and_tests",
                   5: "evidence_collection", 6: "gap_analysis", 7: "audit_prep", 8: "ongoing"}

    return jsonify({
        "journey": {
            "current_phase": current_phase,
            "current_phase_name": phase_names[current_phase],
            "phases": phases,
            "next_actions": next_actions[:3],
            "compliance_score": overall_score,
            "soc2_stage": soc2_stage,
        }
    })


@api_bp.route("/controls")
@require_api_key
def list_controls():
    """List all SOC 2 controls.
    ---
    tags:
      - Controls
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: List of all controls
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: string
                  name:
                    type: string
                  category:
                    type: string
                    enum: [security, availability, confidentiality, privacy, processing_integrity]
                  state:
                    type: string
                  description:
                    type: string
      401:
        description: Missing or invalid API key
    """
    controls = Control.query.order_by(Control.category, Control.name).all()
    return jsonify([{
        "id": c.id,
        "name": c.name,
        "category": c.category,
        "state": c.state,
        "description": c.description,
    } for c in controls])


@api_bp.route("/gaps")
@require_api_key
def evidence_gaps():
    """Return tests with missing or outdated evidence.
    ---
    tags:
      - Evidence
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: List of tests needing evidence
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: string
                  name:
                    type: string
                  control_id:
                    type: string
                  evidence_status:
                    type: string
                    enum: [missing, outdated, due_soon]
                  due_at:
                    type: string
                    format: date-time
                    nullable: true
      401:
        description: Missing or invalid API key
    """
    gaps = TestRecord.query.filter(
        TestRecord.evidence_status.in_(["missing", "outdated", "due_soon"])
    ).all()
    return jsonify([{
        "id": t.id,
        "name": t.name,
        "control_id": t.control_id,
        "evidence_status": t.evidence_status,
        "due_at": t.due_at.isoformat() if t.due_at else None,
    } for t in gaps])


@api_bp.route("/decision-log/ingest", methods=["POST"])
@require_api_key
def ingest_decision_logs():
    """Ingest pending session transcripts from decision-logs/ directory.
    ---
    tags:
      - Decision Log
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: Number of sessions ingested
        content:
          application/json:
            schema:
              type: object
              properties:
                ingested:
                  type: integer
                  example: 3
      401:
        description: Missing or invalid API key
    """
    from app.services.transcript_ingest import ingest_all_pending
    count = ingest_all_pending()
    return jsonify({"ingested": count})


@api_bp.route("/decision-log/upload", methods=["POST"])
@require_api_key
def upload_decision_log():
    """Upload a JSONL decision log transcript directly.
    ---
    tags:
      - Decision Log
    security:
      - ApiKeyAuth: []
    parameters:
      - name: session_id
        in: query
        required: false
        schema:
          type: string
        description: Optional session ID. Generated if omitted.
      - name: exit_reason
        in: query
        required: false
        schema:
          type: string
        description: Session exit reason.
    requestBody:
      required: true
      content:
        application/jsonl:
          schema:
            type: string
            description: JSONL transcript content
    responses:
      200:
        description: Session ingested successfully
        content:
          application/json:
            schema:
              type: object
              properties:
                session_id:
                  type: string
                entries:
                  type: integer
      400:
        description: Empty content or duplicate session
      401:
        description: Missing or invalid API key
    """
    content = request.get_data(as_text=True)
    if not content or not content.strip():
        return jsonify({"error": "Empty request body"}), 400

    session_id = request.args.get("session_id") or str(uuid.uuid4())
    exit_reason = request.args.get("exit_reason")

    from app.services.transcript_ingest import ingest_from_content
    session = ingest_from_content(
        content=content,
        session_id=session_id,
        submitted_by=g.current_team_member.id,
        exit_reason=exit_reason,
    )

    if session is None:
        return jsonify({"error": "Session already exists", "session_id": session_id}), 400

    entry_count = session.interactions.count()
    return jsonify({"session_id": session.id, "entries": entry_count})


@api_bp.route("/decision-log/sessions")
@require_api_key
def list_sessions():
    """List all ingested decision log sessions.
    ---
    tags:
      - Decision Log
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: List of sessions with metadata
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: string
                  agent_type:
                    type: string
                  model:
                    type: string
                  git_branch:
                    type: string
                  started_at:
                    type: string
                    format: date-time
                  ended_at:
                    type: string
                    format: date-time
                  submitted_by:
                    type: string
                  entry_count:
                    type: integer
                  verifications:
                    type: integer
      401:
        description: Missing or invalid API key
    """
    sessions = DecisionLogSession.query.order_by(DecisionLogSession.started_at.desc()).all()
    return jsonify([{
        "id": s.id,
        "agent_type": s.agent_type,
        "model": s.model,
        "git_branch": s.git_branch,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "ended_at": s.ended_at.isoformat() if s.ended_at else None,
        "submitted_by": s.submitted_by,
        "entry_count": s.interactions.count(),
        "verifications": s.interactions.filter_by(is_verification=True).count(),
    } for s in sessions])


@api_bp.route("/decision-log/session/<session_id>")
@require_api_key
def get_session(session_id):
    """Get a session's entries (the decision log).
    ---
    tags:
      - Decision Log
    security:
      - ApiKeyAuth: []
    parameters:
      - name: session_id
        in: path
        required: true
        schema:
          type: string
        description: The session ID
    responses:
      200:
        description: Session details with all entries
      401:
        description: Missing or invalid API key
      404:
        description: Session not found
    """
    session = DecisionLogSession.query.get_or_404(session_id)
    entries = session.interactions.all()
    return jsonify({
        "session": {
            "id": session.id,
            "agent_type": session.agent_type,
            "model": session.model,
            "cwd": session.cwd,
            "git_branch": session.git_branch,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "ended_at": session.ended_at.isoformat() if session.ended_at else None,
            "submitted_by": session.submitted_by,
        },
        "entries": [{
            "role": e.role,
            "content_text": e.content_text,
            "has_tool_calls": e.tool_calls is not None,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "is_verification": e.is_verification,
        } for e in entries],
    })


@api_bp.route("/audit-log")
@require_api_key
def audit_log():
    """Query the audit log for compliance data changes.
    ---
    tags:
      - Audit
    security:
      - ApiKeyAuth: []
    parameters:
      - name: table
        in: query
        required: false
        schema:
          type: string
        description: Filter by table name (e.g., controls, policies)
      - name: record_id
        in: query
        required: false
        schema:
          type: string
        description: Filter by record ID
      - name: action
        in: query
        required: false
        schema:
          type: string
          enum: [INSERT, UPDATE, DELETE]
        description: Filter by action type
      - name: changed_by
        in: query
        required: false
        schema:
          type: string
        description: Filter by team member ID
      - name: since
        in: query
        required: false
        schema:
          type: string
          format: date-time
        description: Only return entries after this timestamp
      - name: limit
        in: query
        required: false
        schema:
          type: integer
          default: 50
          maximum: 200
        description: Maximum number of entries to return
    responses:
      200:
        description: List of audit log entries
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                  table_name:
                    type: string
                  record_id:
                    type: string
                  action:
                    type: string
                  old_values:
                    type: object
                  new_values:
                    type: object
                  changed_by:
                    type: string
                  changed_at:
                    type: string
                    format: date-time
      401:
        description: Missing or invalid API key
    """
    from app.models.audit_log import AuditLog

    query = AuditLog.query

    table_filter = request.args.get("table")
    if table_filter:
        query = query.filter_by(table_name=table_filter)

    record_id = request.args.get("record_id")
    if record_id:
        query = query.filter_by(record_id=record_id)

    action = request.args.get("action")
    if action:
        query = query.filter_by(action=action.upper())

    changed_by = request.args.get("changed_by")
    if changed_by:
        query = query.filter_by(changed_by=changed_by)

    since = request.args.get("since")
    if since:
        from datetime import datetime
        try:
            since_dt = datetime.fromisoformat(since)
            query = query.filter(AuditLog.changed_at >= since_dt)
        except ValueError:
            pass

    limit = min(int(request.args.get("limit", 50)), 200)
    entries = query.order_by(AuditLog.changed_at.desc()).limit(limit).all()

    from app.models.team_member import TeamMember
    member_ids = {e.changed_by for e in entries if e.changed_by}
    members = {}
    if member_ids:
        for m in TeamMember.query.filter(TeamMember.id.in_(member_ids)).all():
            members[m.id] = m.name

    return jsonify([{
        "id": e.id,
        "table_name": e.table_name,
        "record_id": e.record_id,
        "action": e.action,
        "old_values": e.old_values,
        "new_values": e.new_values,
        "changed_by": e.changed_by,
        "changed_by_name": members.get(e.changed_by) if e.changed_by else None,
        "changed_at": e.changed_at.isoformat() if e.changed_at else None,
    } for e in entries])


@api_bp.route("/audit-log/verify")
@require_api_key
def verify_audit_log():
    """Verify the integrity of the audit log hash chain.
    ---
    tags:
      - Audit
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: Verification result
        content:
          application/json:
            schema:
              type: object
              properties:
                status:
                  type: string
                  enum: [valid, broken, empty, no_hashes]
                total_entries:
                  type: integer
                verified:
                  type: integer
                chain_head:
                  type: string
                  description: The most recent row_hash
                first_break:
                  type: object
                  nullable: true
                  description: Details of the first broken link, if any
      401:
        description: Missing or invalid API key
    """
    from app.models.audit_log import AuditLog

    total = AuditLog.query.count()

    if total == 0:
        return jsonify({
            "status": "empty",
            "total_entries": 0,
            "verified": 0,
            "chain_head": None,
            "first_break": None,
        })

    # Fetch only the hash columns in order — avoids loading full row data
    rows = (
        db.session.query(AuditLog.id, AuditLog.row_hash, AuditLog.previous_hash)
        .order_by(AuditLog.id.asc())
        .all()
    )

    # Check if hash chain is populated (pre-migration entries won't have hashes)
    hashed_rows = [(r.id, r.row_hash, r.previous_hash) for r in rows if r.row_hash]

    if not hashed_rows:
        return jsonify({
            "status": "no_hashes",
            "total_entries": total,
            "verified": 0,
            "chain_head": None,
            "first_break": None,
            "message": "No hash chain data found. Entries predate the hash chain migration.",
        })

    genesis_hash = "0" * 64
    verified = 0
    first_break = None

    for i, (entry_id, row_hash, previous_hash) in enumerate(hashed_rows):
        expected_prev = hashed_rows[i - 1][1] if i > 0 else genesis_hash

        if previous_hash != expected_prev:
            first_break = {
                "id": entry_id,
                "position": i,
                "issue": "Chain break: previous_hash does not match preceding entry's row_hash",
                "expected": expected_prev,
                "actual": previous_hash,
            }
            break

        verified += 1

    chain_head = hashed_rows[-1][1]

    return jsonify({
        "status": "valid" if first_break is None else "broken",
        "total_entries": total,
        "hashed_entries": len(hashed_rows),
        "verified": verified,
        "chain_head": chain_head,
        "first_break": first_break,
    })


@api_bp.route("/settings", methods=["GET"])
@require_api_key
def get_settings():
    """Get portal settings.
    ---
    tags:
      - Settings
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: Current portal settings
      401:
        description: Missing or invalid API key
    """
    from app.services.settings_service import get_portal_settings
    return jsonify(get_portal_settings())


@api_bp.route("/settings", methods=["PUT"])
@require_api_key
@require_admin
def update_settings():
    """Update portal settings (admin only).
    ---
    tags:
      - Settings
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: Updated portal settings
      401:
        description: Missing or invalid API key
      403:
        description: Not a compliance admin
    """
    from app.services.settings_service import update_portal_settings, get_portal_settings as _get
    data = request.get_json()
    update_portal_settings(data, updated_by=g.current_team_member.id)
    return jsonify(_get())


def _create_evidence_items(items, test_record_id):
    """Create Evidence records from a list of evidence item dicts.

    Returns (created_count, error_message). If error_message is not None,
    the caller should return a 400 response with that message.
    """
    for item in items:
        if "evidence_type" not in item or "description" not in item:
            return 0, "Each evidence item requires evidence_type and description"

        file_bytes = None
        if "file_data" in item and isinstance(item["file_data"], str):
            try:
                file_bytes = base64.b64decode(item["file_data"])
            except Exception:
                return 0, "Invalid base64 in evidence file_data"

        ev = Evidence(
            id=str(uuid.uuid4()),
            test_record_id=test_record_id,
            evidence_type=item["evidence_type"],
            description=item["description"],
            url=item.get("url"),
            file_path=item.get("file_path"),
            file_data=file_bytes,
            file_name=item.get("file_name"),
            file_mime_type=item.get("file_mime_type"),
            collected_at=datetime.now(timezone.utc),
        )
        db.session.add(ev)

    return len(items), None


def _apply_execution(test, data):
    """Apply execution result fields to a TestRecord.

    Returns error_message or None on success.
    """
    outcome = data.get("outcome")
    if not outcome:
        return "Missing required field: outcome"
    if outcome not in ("success", "failure"):
        return "outcome must be 'success' or 'failure'"

    test.execution_status = "completed"
    test.execution_outcome = outcome
    test.status = "passed" if outcome == "success" else "failed"
    test.last_executed_at = datetime.now(timezone.utc)

    if "finding" in data:
        test.finding = data["finding"]
    if "comment" in data:
        test.comment = data["comment"]

    evidence_items = data.get("evidence", [])
    if evidence_items:
        count, err = _create_evidence_items(evidence_items, test.id)
        if err:
            return err
        test.evidence_status = "submitted"

    return None


@api_bp.route("/tests/<test_id>/record-execution", methods=["POST"])
@require_api_key
def record_execution(test_id):
    """Record the result of an externally-performed test execution.
    ---
    tags:
      - Tests
    security:
      - ApiKeyAuth: []
    parameters:
      - name: test_id
        in: path
        required: true
        schema:
          type: string
        description: The test record ID
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - outcome
            properties:
              outcome:
                type: string
                enum: [success, failure]
                description: Test result — success or failure
              finding:
                type: string
                description: Description of what was found
              comment:
                type: string
                description: Additional reviewer notes
              evidence:
                type: array
                description: Optional evidence items to attach to this test
                items:
                  type: object
                  required:
                    - evidence_type
                    - description
                  properties:
                    evidence_type:
                      type: string
                      enum: [link, file, screenshot, automated]
                    description:
                      type: string
                    url:
                      type: string
                      description: URL for link-type evidence
                    file_path:
                      type: string
                      description: Path for file-type evidence
    responses:
      200:
        description: Updated test record with execution result and any created evidence
        content:
          application/json:
            schema:
              type: object
              properties:
                test:
                  type: object
                  description: Updated test record
                evidence_created:
                  type: integer
                  description: Number of evidence items created (0 if none provided)
      400:
        description: Missing or invalid outcome
      401:
        description: Missing or invalid API key
      404:
        description: Test record not found
    """
    test = db.session.get(TestRecord, test_id)
    if not test:
        return jsonify({"error": "Test record not found"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    err = _apply_execution(test, data)
    if err:
        return jsonify({"error": err}), 400

    db.session.commit()

    from app.routes.crud import _serialize
    result = _serialize(test)
    result["evidence_created"] = len(data.get("evidence", []))
    return jsonify(result)


@api_bp.route("/tests/batch-record-execution", methods=["POST"])
@require_api_key
def batch_record_execution():
    """Record execution results for multiple tests in one call.
    ---
    tags:
      - Tests
    security:
      - ApiKeyAuth: []
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - executions
            properties:
              executions:
                type: array
                items:
                  type: object
                  required:
                    - test_id
                    - outcome
                  properties:
                    test_id:
                      type: string
                    outcome:
                      type: string
                      enum: [success, failure]
                    finding:
                      type: string
                    comment:
                      type: string
                    evidence:
                      type: array
                      items:
                        type: object
    responses:
      200:
        description: Per-item results with success/failure counts
      400:
        description: Missing executions array
      401:
        description: Missing or invalid API key
    """
    data = request.get_json()
    if not data or "executions" not in data:
        return jsonify({"error": "Missing required field: executions"}), 400

    items = data["executions"]
    if not isinstance(items, list):
        return jsonify({"error": "executions must be an array"}), 400

    results = []
    succeeded = 0
    failed = 0

    for item in items:
        test_id = item.get("test_id")
        if not test_id:
            results.append({"test_id": None, "status": "error", "message": "Missing test_id"})
            failed += 1
            continue

        test = db.session.get(TestRecord, test_id)
        if not test:
            results.append({"test_id": test_id, "status": "error", "message": "Test record not found"})
            failed += 1
            continue

        err = _apply_execution(test, item)
        if err:
            results.append({"test_id": test_id, "status": "error", "message": err})
            failed += 1
            continue

        results.append({"test_id": test_id, "status": "ok", "outcome": item["outcome"]})
        succeeded += 1

    db.session.commit()

    return jsonify({"results": results, "succeeded": succeeded, "failed": failed})


@api_bp.route("/evidence/batch-submit", methods=["POST"])
@require_api_key
def batch_submit_evidence():
    """Submit evidence for multiple tests in one call.
    ---
    tags:
      - Evidence
    security:
      - ApiKeyAuth: []
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - evidence
            properties:
              evidence:
                type: array
                items:
                  type: object
                  required:
                    - test_record_id
                    - evidence_type
                    - description
                  properties:
                    test_record_id:
                      type: string
                    evidence_type:
                      type: string
                      enum: [link, file, screenshot, automated]
                    description:
                      type: string
                    url:
                      type: string
                    file_data:
                      type: string
                      description: Base64-encoded file content
                    file_name:
                      type: string
                    file_mime_type:
                      type: string
    responses:
      200:
        description: Per-item results with success/failure counts
      400:
        description: Missing evidence array
      401:
        description: Missing or invalid API key
    """
    data = request.get_json()
    if not data or "evidence" not in data:
        return jsonify({"error": "Missing required field: evidence"}), 400

    items = data["evidence"]
    if not isinstance(items, list):
        return jsonify({"error": "evidence must be an array"}), 400

    results = []
    succeeded = 0
    failed = 0
    tests_updated = set()

    for item in items:
        test_record_id = item.get("test_record_id")
        if not test_record_id:
            results.append({"test_record_id": None, "status": "error", "message": "Missing test_record_id"})
            failed += 1
            continue

        test = db.session.get(TestRecord, test_record_id)
        if not test:
            results.append({"test_record_id": test_record_id, "status": "error", "message": "Test record not found"})
            failed += 1
            continue

        count, err = _create_evidence_items([item], test_record_id)
        if err:
            results.append({"test_record_id": test_record_id, "status": "error", "message": err})
            failed += 1
            continue

        tests_updated.add(test_record_id)
        results.append({"test_record_id": test_record_id, "status": "ok"})
        succeeded += 1

    for tid in tests_updated:
        test = db.session.get(TestRecord, tid)
        if test:
            test.evidence_status = "submitted"

    db.session.commit()

    return jsonify({"results": results, "succeeded": succeeded, "failed": failed})


@api_bp.route("/tests/<test_id>/execution-history")
@require_api_key
def execution_history(test_id):
    """Get the execution history for a test record, derived from the audit log.
    ---
    tags:
      - Tests
    security:
      - ApiKeyAuth: []
    parameters:
      - name: test_id
        in: path
        required: true
        schema:
          type: string
        description: The test record ID
      - name: limit
        in: query
        required: false
        schema:
          type: integer
          default: 20
          maximum: 100
        description: Maximum number of entries to return
    responses:
      200:
        description: List of execution events
        content:
          application/json:
            schema:
              type: object
              properties:
                test_id:
                  type: string
                executions:
                  type: array
                  items:
                    type: object
                    properties:
                      execution_outcome:
                        type: string
                      execution_status:
                        type: string
                      status:
                        type: string
                      finding:
                        type: string
                      comment:
                        type: string
                      changed_by:
                        type: string
                      changed_by_name:
                        type: string
                      changed_at:
                        type: string
                        format: date-time
      401:
        description: Missing or invalid API key
      404:
        description: Test record not found
    """
    test = db.session.get(TestRecord, test_id)
    if not test:
        return jsonify({"error": "Test record not found"}), 404

    from app.models.audit_log import AuditLog

    limit = min(int(request.args.get("limit", 20)), 100)

    execution_fields = {"execution_status", "execution_outcome", "last_executed_at"}

    entries = (
        AuditLog.query
        .filter_by(table_name="test_records", record_id=test_id)
        .filter(AuditLog.action.in_(["UPDATE", "INSERT"]))
        .order_by(AuditLog.changed_at.desc())
        .all()
    )

    executions = []
    for entry in entries:
        new_vals = entry.new_values or {}
        if not execution_fields.intersection(new_vals.keys()):
            continue
        executions.append({
            "execution_outcome": new_vals.get("execution_outcome"),
            "execution_status": new_vals.get("execution_status"),
            "status": new_vals.get("status"),
            "finding": new_vals.get("finding"),
            "comment": new_vals.get("comment"),
            "changed_by": entry.changed_by,
            "changed_at": entry.changed_at.isoformat() if entry.changed_at else None,
        })
        if len(executions) >= limit:
            break

    from app.models.team_member import TeamMember
    member_ids = {e["changed_by"] for e in executions if e["changed_by"]}
    members = {}
    if member_ids:
        for m in TeamMember.query.filter(TeamMember.id.in_(member_ids)).all():
            members[m.id] = m.name
    for e in executions:
        e["changed_by_name"] = members.get(e["changed_by"]) if e["changed_by"] else None

    return jsonify({"test_id": test_id, "executions": executions})


@api_bp.route("/evidence/<evidence_id>/download")
@require_api_key
def download_evidence(evidence_id):
    """Download an evidence file stored in the database.
    ---
    tags:
      - Evidence
    security:
      - ApiKeyAuth: []
    parameters:
      - name: evidence_id
        in: path
        required: true
        schema:
          type: string
        description: The evidence record ID
    responses:
      200:
        description: The evidence file
        content:
          application/octet-stream:
            schema:
              type: string
              format: binary
      404:
        description: Evidence not found or has no file
      401:
        description: Missing or invalid API key
    """
    ev = db.session.get(Evidence, evidence_id)
    if not ev:
        return jsonify({"error": "Evidence not found"}), 404
    if not ev.file_data:
        return jsonify({"error": "No file stored for this evidence record"}), 404

    return Response(
        ev.file_data,
        mimetype=ev.file_mime_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{ev.file_name or evidence_id}"',
        },
    )


@api_bp.route("/openapi.json")
def openapi_spec():
    """Serve the raw OpenAPI specification as JSON.
    ---
    tags:
      - System
    responses:
      200:
        description: OpenAPI 3.0 specification
    """
    from flask import current_app
    spec = current_app.extensions.get("swagger").get_apispecs()
    return jsonify(spec)
