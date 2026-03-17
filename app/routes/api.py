"""Internal API routes for programmatic access."""

import logging
import uuid

from flask import Blueprint, jsonify, request, g

from app.models import db, Control, Policy, TestRecord, Evidence, DecisionLogSession, DecisionLogEntry
from app.auth import require_api_key

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
                  example: mgcompliance
                database:
                  type: string
                  example: connected
      503:
        description: Service is degraded (database unreachable)
    """
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify({"status": "ok", "service": "mgcompliance", "database": "connected"})
    except Exception:
        logger.warning("Health check: database unreachable")
        return jsonify({"status": "degraded", "service": "mgcompliance", "database": "unreachable"}), 503


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
