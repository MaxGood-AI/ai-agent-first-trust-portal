"""Admin routes for managing compliance artifacts."""

import uuid as _uuid
from datetime import datetime, timezone

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, g, Response

from app.models import db, Control, System, Vendor, Policy, TestRecord, Evidence, RiskRegister, TeamMember
from app.auth import require_api_key, require_admin, require_client_or_admin
from app.services import team_service

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    """Login page — paste API key to access admin."""
    if request.method == "POST":
        api_key = request.form.get("api_key", "").strip()
        if not api_key:
            return render_template("admin/login.html", error="Please enter an API key.")

        member = TeamMember.query.filter_by(api_key=api_key, is_active=True).first()
        if not member:
            return render_template("admin/login.html", error="Invalid or inactive API key.")

        if not member.is_compliance_admin:
            return render_template("admin/login.html", error="This account does not have admin access.")

        session["api_key"] = api_key
        next_url = request.args.get("next", url_for("admin.dashboard"))
        return redirect(next_url)

    error = None
    if request.args.get("error") == "invalid":
        error = "Your session has expired. Please log in again."
    elif request.args.get("error") == "forbidden":
        error = "Admin access required."
    return render_template("admin/login.html", error=error)


@admin_bp.route("/logout")
def logout():
    """Clear session and redirect to login."""
    session.pop("api_key", None)
    return redirect(url_for("admin.login"))


@admin_bp.route("/")
@require_api_key
@require_admin
def dashboard():
    """Admin dashboard showing compliance management overview."""
    from app.services.collector_status import get_overview as get_collector_overview

    total_controls = Control.query.count()
    total_tests = TestRecord.query.count()
    missing_evidence = TestRecord.query.filter_by(evidence_status="missing").count()
    outdated_evidence = TestRecord.query.filter_by(evidence_status="outdated").count()
    total_policies = Policy.query.count()
    approved_policies = Policy.query.filter_by(status="approved").count()
    total_members = TeamMember.query.filter_by(is_active=True).count()

    collector_overview = get_collector_overview()

    return render_template(
        "admin/dashboard.html",
        total_controls=total_controls,
        total_tests=total_tests,
        missing_evidence=missing_evidence,
        outdated_evidence=outdated_evidence,
        total_policies=total_policies,
        approved_policies=approved_policies,
        gaps=missing_evidence + outdated_evidence,
        total_members=total_members,
        collector_overview=collector_overview,
    )


@admin_bp.route("/evidence")
@require_api_key
@require_admin
def evidence_management():
    """Evidence management view — shows tests needing evidence and existing evidence."""
    tests_needing_attention = TestRecord.query.filter(
        TestRecord.evidence_status.in_(["missing", "outdated", "due_soon"])
    ).order_by(TestRecord.evidence_status, TestRecord.due_at).all()

    all_evidence = Evidence.query.order_by(Evidence.created_at.desc()).limit(100).all()
    all_tests = TestRecord.query.order_by(TestRecord.name).all()

    return render_template(
        "admin/evidence.html",
        tests=tests_needing_attention,
        evidence=all_evidence,
        all_tests=all_tests,
    )


@admin_bp.route("/evidence/upload", methods=["POST"])
@require_api_key
@require_admin
def evidence_upload():
    """Upload evidence file via the admin UI."""
    test_record_id = request.form.get("test_record_id", "").strip()
    evidence_type = request.form.get("evidence_type", "file")
    description = request.form.get("description", "").strip()
    url = request.form.get("url", "").strip() or None

    if not test_record_id or not description:
        flash("Test record and description are required.", "error")
        return redirect(url_for("admin.evidence_management"))

    test = db.session.get(TestRecord, test_record_id)
    if not test:
        flash("Test record not found.", "error")
        return redirect(url_for("admin.evidence_management"))

    file_data = None
    file_name = None
    file_mime_type = None

    uploaded_file = request.files.get("file")
    if uploaded_file and uploaded_file.filename:
        file_data = uploaded_file.read()
        file_name = uploaded_file.filename
        file_mime_type = uploaded_file.content_type or "application/octet-stream"

    ev = Evidence(
        id=str(_uuid.uuid4()),
        test_record_id=test_record_id,
        evidence_type=evidence_type,
        description=description,
        url=url,
        file_data=file_data,
        file_name=file_name,
        file_mime_type=file_mime_type,
        collected_at=datetime.now(timezone.utc),
    )
    db.session.add(ev)

    test.evidence_status = "submitted"
    db.session.commit()

    flash(f"Evidence submitted: {description}", "success")
    return redirect(url_for("admin.evidence_management"))


@admin_bp.route("/evidence/<evidence_id>/download")
@require_api_key
@require_admin
def evidence_download(evidence_id):
    """Download an evidence file from the admin UI."""
    ev = db.session.get(Evidence, evidence_id)
    if not ev or not ev.file_data:
        flash("Evidence file not found.", "error")
        return redirect(url_for("admin.evidence_management"))

    return Response(
        ev.file_data,
        mimetype=ev.file_mime_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{ev.file_name or evidence_id}"',
        },
    )


@admin_bp.route("/team")
@require_api_key
@require_admin
def team_management():
    """Team member management view."""
    members = team_service.list_members(include_inactive=True)
    return render_template("admin/team_members.html", members=members)


@admin_bp.route("/team", methods=["POST"])
@require_api_key
@require_admin
def create_team_member():
    """Create a new team member."""
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "human")
    is_admin = request.form.get("is_compliance_admin") == "on"
    company = request.form.get("company", "").strip() or None
    expires_at_str = request.form.get("expires_at", "").strip()

    if not name or not email:
        flash("Name and email are required.", "error")
        return redirect(url_for("admin.team_management"))

    if role not in ("human", "agent", "client"):
        flash("Role must be 'human', 'agent', or 'client'.", "error")
        return redirect(url_for("admin.team_management"))

    expires_at = None
    if expires_at_str:
        from datetime import datetime, timezone
        try:
            expires_at = datetime.strptime(expires_at_str, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
        except ValueError:
            flash("Invalid expiry date format.", "error")
            return redirect(url_for("admin.team_management"))

    member = team_service.create_member(
        name, email, role,
        is_compliance_admin=is_admin,
        company=company,
        expires_at=expires_at,
    )
    flash(f"Created {member.name}. API key: {member.api_key}", "success")
    return redirect(url_for("admin.team_management"))


@admin_bp.route("/team/<member_id>/deactivate", methods=["POST"])
@require_api_key
@require_admin
def deactivate_team_member(member_id):
    """Deactivate a team member."""
    member = team_service.deactivate_member(member_id)
    if member:
        flash(f"Deactivated {member.name}.", "success")
    else:
        flash("Team member not found.", "error")
    return redirect(url_for("admin.team_management"))


@admin_bp.route("/team/<member_id>/regenerate-key", methods=["POST"])
@require_api_key
@require_admin
def regenerate_team_member_key(member_id):
    """Generate a new API key for a team member."""
    member = team_service.regenerate_key(member_id)
    if member:
        flash(f"New API key for {member.name}: {member.api_key}", "success")
    else:
        flash("Team member not found.", "error")
    return redirect(url_for("admin.team_management"))


# --- Admin CRUD for core entities ---

import uuid
from sqlalchemy import inspect as sa_inspect


def _admin_entity_list(model_class, display_name):
    """Generic admin list view for an entity type."""
    items = model_class.query.all()
    return render_template(
        "admin/entity_list.html",
        items=items,
        display_name=display_name,
    )


def _admin_entity_create(model_class, redirect_endpoint, required_fields):
    """Generic admin create handler."""
    data = {}
    mapper = sa_inspect(model_class)
    valid_columns = {attr.key for attr in mapper.column_attrs}

    for key in valid_columns:
        if key in ("id", "created_at", "updated_at", "other_data"):
            continue
        value = request.form.get(key, "").strip()
        if value:
            data[key] = value

    for field in required_fields:
        if field not in data:
            flash(f"Missing required field: {field}", "error")
            return redirect(url_for(redirect_endpoint))

    data["id"] = str(uuid.uuid4())
    instance = model_class(**data)
    db.session.add(instance)
    db.session.commit()
    flash(f"Created: {data.get('name', data.get('title', data['id']))}", "success")
    return redirect(url_for(redirect_endpoint))


def _admin_entity_delete(model_class, item_id, redirect_endpoint):
    """Generic admin delete handler."""
    item = db.session.get(model_class, item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
        flash("Deleted.", "success")
    else:
        flash("Not found.", "error")
    return redirect(url_for(redirect_endpoint))


@admin_bp.route("/controls")
@require_api_key
@require_admin
def admin_controls():
    return _admin_entity_list(Control, "Controls")


@admin_bp.route("/controls", methods=["POST"])
@require_api_key
@require_admin
def admin_controls_create():
    return _admin_entity_create(Control, "admin.admin_controls", ["name", "category"])


@admin_bp.route("/controls/<item_id>/delete", methods=["POST"])
@require_api_key
@require_admin
def admin_controls_delete(item_id):
    return _admin_entity_delete(Control, item_id, "admin.admin_controls")


@admin_bp.route("/systems")
@require_api_key
@require_admin
def admin_systems():
    return _admin_entity_list(System, "Systems")


@admin_bp.route("/systems", methods=["POST"])
@require_api_key
@require_admin
def admin_systems_create():
    return _admin_entity_create(System, "admin.admin_systems", ["name"])


@admin_bp.route("/systems/<item_id>/delete", methods=["POST"])
@require_api_key
@require_admin
def admin_systems_delete(item_id):
    return _admin_entity_delete(System, item_id, "admin.admin_systems")


@admin_bp.route("/vendors")
@require_api_key
@require_admin
def admin_vendors():
    return _admin_entity_list(Vendor, "Vendors")


@admin_bp.route("/vendors", methods=["POST"])
@require_api_key
@require_admin
def admin_vendors_create():
    return _admin_entity_create(Vendor, "admin.admin_vendors", ["name"])


@admin_bp.route("/vendors/<item_id>/delete", methods=["POST"])
@require_api_key
@require_admin
def admin_vendors_delete(item_id):
    return _admin_entity_delete(Vendor, item_id, "admin.admin_vendors")


@admin_bp.route("/policies")
@require_api_key
@require_admin
def admin_policies():
    return _admin_entity_list(Policy, "Policies")


@admin_bp.route("/policies", methods=["POST"])
@require_api_key
@require_admin
def admin_policies_create():
    return _admin_entity_create(Policy, "admin.admin_policies", ["title", "category"])


@admin_bp.route("/policies/<item_id>/delete", methods=["POST"])
@require_api_key
@require_admin
def admin_policies_delete(item_id):
    return _admin_entity_delete(Policy, item_id, "admin.admin_policies")


@admin_bp.route("/risks")
@require_api_key
@require_admin
def admin_risks():
    return _admin_entity_list(RiskRegister, "Risk Register")


@admin_bp.route("/risks", methods=["POST"])
@require_api_key
@require_admin
def admin_risks_create():
    return _admin_entity_create(RiskRegister, "admin.admin_risks", ["name"])


@admin_bp.route("/risks/<item_id>/delete", methods=["POST"])
@require_api_key
@require_admin
def admin_risks_delete(item_id):
    return _admin_entity_delete(RiskRegister, item_id, "admin.admin_risks")


@admin_bp.route("/audit-log")
@require_api_key
@require_admin
def admin_audit_log():
    from app.models.audit_log import AuditLog

    query = AuditLog.query

    table_filter = request.args.get("table")
    if table_filter:
        query = query.filter_by(table_name=table_filter)

    record_id = request.args.get("record_id")
    if record_id:
        query = query.filter_by(record_id=record_id)

    action_filter = request.args.get("action")
    if action_filter:
        query = query.filter_by(action=action_filter.upper())

    page = int(request.args.get("page", 1))
    per_page = 50
    pagination = query.order_by(AuditLog.changed_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    audited_tables = [
        "controls", "test_records", "policies", "evidence",
        "systems", "vendors", "risk_register", "pentest_findings",
        "team_members",
    ]

    # Resolve changed_by UUIDs to member names
    member_ids = {e.changed_by for e in pagination.items if e.changed_by}
    members = {}
    if member_ids:
        for m in TeamMember.query.filter(TeamMember.id.in_(member_ids)).all():
            members[m.id] = m.name

    return render_template(
        "admin/audit_log.html",
        entries=pagination.items,
        pagination=pagination,
        audited_tables=audited_tables,
        members=members,
        current_table=table_filter or "",
        current_record_id=record_id or "",
        current_action=action_filter or "",
    )


@admin_bp.route("/settings", methods=["GET"])
@require_api_key
@require_admin
def admin_settings():
    from app.services.settings_service import get_portal_settings, SOC2_STAGES
    settings = get_portal_settings()
    return render_template("admin/settings.html", settings=settings, soc2_stages=SOC2_STAGES)


@admin_bp.route("/settings", methods=["POST"])
@require_api_key
@require_admin
def admin_settings_update():
    from app.services.settings_service import update_portal_settings
    data = {
        "company_legal_name": request.form.get("company_legal_name") or None,
        "company_brand_name": request.form.get("company_brand_name") or None,
        "contact_email": request.form.get("contact_email") or None,
        "physical_address": request.form.get("physical_address") or None,
        "website_url": request.form.get("website_url") or None,
        "soc2_current_stage": request.form.get("soc2_current_stage", "not_started"),
        "soc2_stage_dates": {
            "type_1_completed": request.form.get("type_1_date") or None,
            "type_2_completed": request.form.get("type_2_date") or None,
        },
        "legal_content_md": request.form.get("legal_content_md") or None,
        "legal_external_url": request.form.get("legal_external_url") or None,
        "ai_transparency_md": request.form.get("ai_transparency_md") or None,
    }
    update_portal_settings(data, updated_by=g.current_team_member.id)
    flash("Settings updated successfully.", "success")
    return redirect(url_for("admin.admin_settings"))


# --- Client access (#651) ---


@admin_bp.route("/client-login", methods=["GET", "POST"])
def client_login():
    """Client login page — paste API key to access compliance report."""
    if request.method == "GET":
        return render_template("admin/client_login.html",
                               error=request.args.get("error"))

    api_key = request.form.get("api_key", "").strip()
    member = TeamMember.query.filter_by(api_key=api_key, is_active=True).first()

    if not member or member.role != "client":
        return render_template("admin/client_login.html",
                               error="Invalid access key")

    if member.is_expired:
        return render_template("admin/client_login.html",
                               error="Your access has expired. Contact the organization for renewal.")

    session["api_key"] = api_key
    return redirect(url_for("admin.client_report"))


@admin_bp.route("/report")
@require_api_key
@require_client_or_admin
def client_report():
    """Comprehensive read-only compliance report for client reviewers."""
    from app.services.compliance_engine import get_compliance_summary
    from app.services.settings_service import get_portal_settings
    from app.models import (
        Control, Policy, System, Vendor, PentestFinding, TestRecord,
    )
    from sqlalchemy import func

    summary = get_compliance_summary()

    # Controls grouped by category with test pass rates
    categories = {}
    for category in ["security", "availability", "confidentiality", "privacy", "processing_integrity"]:
        cat_controls = Control.query.filter_by(category=category).order_by(Control.name).all()
        control_data = []
        for ctrl in cat_controls:
            tests = TestRecord.query.filter_by(control_id=ctrl.id).all()
            control_data.append({
                "control": ctrl,
                "passed": sum(1 for t in tests if t.status == "passed"),
                "total": len(tests),
            })
        categories[category] = control_data

    policies = Policy.query.filter_by(status="approved").order_by(Policy.category, Policy.title).all()
    systems = System.query.order_by(System.name).all()
    vendors = Vendor.query.order_by(Vendor.name).all()

    # Pentest severity counts from the most recent scan only
    latest_scan = db.session.query(PentestFinding.scan_id).order_by(
        PentestFinding.timestamp.desc()
    ).limit(1).scalar()
    if latest_scan:
        pentest_rows = db.session.query(
            PentestFinding.severity, func.count(PentestFinding.id)
        ).filter(PentestFinding.scan_id == latest_scan).group_by(
            PentestFinding.severity
        ).all()
        pentest_summary = {row[0]: row[1] for row in pentest_rows}
    else:
        pentest_summary = {}

    # Evidence gaps
    evidence_gaps = TestRecord.query.filter(
        TestRecord.evidence_status.in_(["missing", "outdated", "due_soon"])
    ).order_by(TestRecord.evidence_status).all()

    portal = get_portal_settings()

    return render_template(
        "admin/client_report.html",
        summary=summary,
        categories=categories,
        policies=policies,
        systems=systems,
        vendors=vendors,
        pentest_summary=pentest_summary,
        evidence_gaps=evidence_gaps,
        portal=portal,
    )


# ============================================================================
# Collector management (admin UI for evidence collectors + setup wizard)
# ============================================================================

# Map of known collector names → display labels and short descriptions.
# Unconfigured collectors in this list still appear on the list page so the
# admin can start configuring them from scratch.
_COLLECTOR_CATALOG = {
    "aws": {
        "label": "AWS Infrastructure",
        "description": (
            "Scans IAM, S3, RDS, EC2, CloudTrail, KMS, and other AWS services "
            "for SOC 2 evidence. Requires an IAM role or access keys."
        ),
    },
    "git": {
        "label": "Git / CodeCommit",
        "description": (
            "Collects branch protection, PR reviews, and commit-message "
            "evidence from CodeCommit or GitHub repositories."
        ),
    },
    "platform": {
        "label": "Platform Services",
        "description": (
            "Probes the health and configuration of your own platform services "
            "(internal APIs, deployed apps) for availability evidence."
        ),
    },
    "policy": {
        "label": "Policies",
        "description": (
            "Verifies policy documents are current, approved, and have "
            "up-to-date review dates."
        ),
    },
    "vendor": {
        "label": "Vendors",
        "description": (
            "Checks vendor security pages, SOC 2 report availability, and "
            "last review dates from the portal's vendor inventory."
        ),
    },
}


@admin_bp.route("/collectors")
@require_api_key
@require_admin
def collectors_list():
    """Admin list of all collectors (configured + unconfigured)."""
    from app.models.collector_config import CollectorConfig
    from app.services import collector_scheduler

    configs = {c.name: c for c in CollectorConfig.query.all()}
    jobs_by_config_id = {}
    for job in collector_scheduler.list_scheduled_jobs():
        if job["id"].startswith("collector-"):
            jobs_by_config_id[job["id"][len("collector-"):]] = job

    rows = []
    for name, meta in _COLLECTOR_CATALOG.items():
        config = configs.get(name)
        scheduled_job = jobs_by_config_id.get(config.id) if config else None
        rows.append({
            "name": name,
            "label": meta["label"],
            "description": meta["description"],
            "config": config,
            "next_run_time": scheduled_job["next_run_time"] if scheduled_job else None,
        })
    return render_template(
        "admin/collectors_list.html",
        rows=rows,
        scheduler_running=collector_scheduler.is_running(),
    )


def _safe_return_to(value: str | None) -> str | None:
    """Whitelist the ``return_to`` query param so it can only send an admin
    back to one of the expected admin pages — no open redirect vulnerability."""
    allowed = {
        url_for("admin.setup_collectors_welcome"),
        url_for("admin.setup_collectors_finish"),
        url_for("admin.collectors_list"),
    }
    if value and value in allowed:
        return value
    return None


@admin_bp.route("/collectors/<name>", methods=["GET"])
@require_api_key
@require_admin
def collector_configure_form(name):
    """Per-collector configuration page.

    Handles both first-time setup and edit-mode for an existing config.
    Dynamic actions (test connection, probe, run, copy IAM policy) are
    done via the JSON API with fetch() from static/js/collectors.js.

    If the admin arrives from the setup wizard, ``?return_to=...`` sends
    them back to the wizard on successful save instead of back to this
    page.
    """
    from app.models.collector_config import CollectorConfig

    if name not in _COLLECTOR_CATALOG:
        flash(f"Unknown collector: {name}", "error")
        return redirect(url_for("admin.collectors_list"))

    config = CollectorConfig.query.filter_by(name=name).first()
    return_to = _safe_return_to(request.args.get("return_to"))
    return render_template(
        "admin/collector_configure.html",
        name=name,
        catalog_entry=_COLLECTOR_CATALOG[name],
        config=config,
        return_to=return_to,
    )


@admin_bp.route("/collectors/<name>", methods=["POST"])
@require_api_key
@require_admin
def collector_configure_submit(name):
    """Handle the config-save form submission.

    Builds a request body matching POST /api/collectors/<name>/configure
    and invokes the same service helpers so the code path is identical to
    the JSON API (which is also exercised by tests).
    """
    import uuid

    from app.models.collector_config import CollectorConfig
    from app.services.collector_encryption import (
        CollectorEncryptionError,
        encrypt_credentials,
    )
    from app.services.credential_resolver import SUPPORTED_MODES

    if name not in _COLLECTOR_CATALOG:
        flash(f"Unknown collector: {name}", "error")
        return redirect(url_for("admin.collectors_list"))

    credential_mode = request.form.get("credential_mode", "task_role").strip()
    if credential_mode not in SUPPORTED_MODES:
        flash(f"Invalid credential mode: {credential_mode}", "error")
        return redirect(url_for("admin.collector_configure_form", name=name))

    # Validate per-collector config fields BEFORE mutating the DB session,
    # so an invalid form submission can't leave a half-constructed config
    # pending in the session.
    parsed_overrides: dict = {}
    if name == "git":
        repos_raw = (request.form.get("repositories") or "").strip()
        if "repositories" in request.form:
            parsed_overrides["repositories"] = [
                line.strip() for line in repos_raw.splitlines() if line.strip()
            ] or None
        lookback = (request.form.get("lookback_days") or "").strip()
        if lookback:
            try:
                parsed_overrides["lookback_days"] = int(lookback)
            except ValueError:
                flash("lookback_days must be an integer", "error")
                return redirect(url_for("admin.collector_configure_form", name=name))

    if name == "platform":
        services_raw = (request.form.get("services_json") or "").strip()
        if services_raw:
            try:
                import json
                services = json.loads(services_raw)
                if not isinstance(services, list):
                    raise ValueError("services must be a JSON array")
                parsed_overrides["services"] = services
            except (ValueError, TypeError) as exc:
                flash(f"Services JSON invalid: {exc}", "error")
                return redirect(url_for("admin.collector_configure_form", name=name))
        timeout = (request.form.get("http_timeout_seconds") or "").strip()
        if timeout:
            try:
                parsed_overrides["http_timeout_seconds"] = int(timeout)
            except ValueError:
                flash("http_timeout_seconds must be an integer", "error")
                return redirect(url_for("admin.collector_configure_form", name=name))

    if name == "policy":
        warn = (request.form.get("review_warning_days") or "").strip()
        if warn:
            try:
                parsed_overrides["review_warning_days"] = int(warn)
            except ValueError:
                flash("review_warning_days must be an integer", "error")
                return redirect(url_for("admin.collector_configure_form", name=name))

    if name == "vendor":
        parsed_overrides["probe_urls"] = request.form.get("probe_urls") == "on"

    config = CollectorConfig.query.filter_by(name=name).first()
    if not config:
        config = CollectorConfig(id=str(uuid.uuid4()), name=name)
        db.session.add(config)

    config.credential_mode = credential_mode
    config.schedule_cron = (request.form.get("schedule_cron") or "").strip() or None
    config.enabled = request.form.get("enabled") == "on"

    existing_config = dict(config.config or {})
    region = (request.form.get("region") or "").strip()
    if region:
        existing_config["region"] = region
    existing_config.update(parsed_overrides)
    config.config = existing_config

    # Collect mode-specific credentials from the form.
    credentials: dict[str, str] = {}
    if credential_mode == "task_role_assume":
        role_arn = (request.form.get("role_arn") or "").strip()
        if role_arn:
            credentials["role_arn"] = role_arn
        external_id = (request.form.get("external_id") or "").strip()
        if external_id:
            credentials["external_id"] = external_id
        session_name = (request.form.get("session_name") or "").strip()
        if session_name:
            credentials["session_name"] = session_name
    elif credential_mode == "access_keys":
        if name == "platform":
            # Platform collector stores bearer/basic auth under different keys
            bearer = (request.form.get("bearer_token") or "").strip()
            basic_user = (request.form.get("basic_user") or "").strip()
            basic_password = (request.form.get("basic_password") or "").strip()
            if bearer:
                credentials["bearer_token"] = bearer
            if basic_user:
                credentials["basic_user"] = basic_user
            if basic_password:
                credentials["basic_password"] = basic_password
        else:
            access_key_id = (request.form.get("access_key_id") or "").strip()
            secret_access_key = (request.form.get("secret_access_key") or "").strip()
            if access_key_id:
                credentials["access_key_id"] = access_key_id
            if secret_access_key:
                credentials["secret_access_key"] = secret_access_key

    # Only update encrypted credentials if the admin provided something
    # meaningful (preserve existing creds on plain edits that don't touch
    # credential fields).
    if credential_mode in ("task_role", "none"):
        config.encrypted_credentials = None
    elif credentials:
        try:
            config.encrypted_credentials = encrypt_credentials(credentials)
        except CollectorEncryptionError as exc:
            flash(f"Credential encryption failed: {exc}", "error")
            return redirect(url_for("admin.collector_configure_form", name=name))

    member = getattr(g, "current_team_member", None)
    if member:
        if not config.created_by_id:
            config.created_by_id = member.id
        config.updated_by_id = member.id

    db.session.commit()

    # Keep the scheduler in sync with the persisted config.
    from app.services import collector_scheduler
    try:
        collector_scheduler.sync_schedule_for(config)
    except Exception as exc:  # noqa: BLE001
        # Scheduler sync failures shouldn't block the save — log and continue.
        import logging
        logging.getLogger(__name__).exception(
            "Failed to sync scheduler for collector %s: %s", name, exc
        )

    flash(f"Saved {name} collector configuration.", "success")

    return_to = _safe_return_to(request.form.get("return_to"))
    if return_to:
        return redirect(return_to)
    return redirect(url_for("admin.collector_configure_form", name=name))


@admin_bp.route("/collectors/<name>/runs")
@require_api_key
@require_admin
def collector_runs(name):
    """Run history for a single collector."""
    from app.models.collector_config import CollectorConfig
    from app.models.collector_run import CollectorRun

    config = CollectorConfig.query.filter_by(name=name).first()
    if not config:
        flash(f"Collector {name} is not configured yet.", "error")
        return redirect(url_for("admin.collectors_list"))

    runs = (
        CollectorRun.query
        .filter_by(collector_config_id=config.id)
        .order_by(CollectorRun.started_at.desc())
        .limit(100)
        .all()
    )
    return render_template(
        "admin/collector_runs.html",
        name=name,
        catalog_entry=_COLLECTOR_CATALOG.get(name, {}),
        runs=runs,
    )


@admin_bp.route("/collectors/<name>/runs/<run_id>")
@require_api_key
@require_admin
def collector_run_detail(name, run_id):
    """Single run detail with per-check results."""
    from app.models.collector_check_result import CollectorCheckResult
    from app.models.collector_run import CollectorRun

    run = db.session.get(CollectorRun, run_id)
    if not run:
        flash("Run not found.", "error")
        return redirect(url_for("admin.collector_runs", name=name))

    checks = (
        CollectorCheckResult.query
        .filter_by(collector_run_id=run_id)
        .order_by(CollectorCheckResult.check_name)
        .all()
    )
    return render_template(
        "admin/collector_run_detail.html",
        name=name,
        run=run,
        checks=checks,
    )


# ----- First-login setup wizard -----


@admin_bp.route("/setup/collectors")
@require_api_key
@require_admin
def setup_collectors_welcome():
    """Welcome page for the evidence-collection setup wizard.

    Always reachable from the admin dashboard. Shows per-collector progress
    and links to each collector's configuration page in "wizard mode" so
    successful saves return here.
    """
    from app.services.collector_status import get_overview

    overview = get_overview()
    return render_template(
        "admin/setup_collectors_welcome.html",
        overview=overview,
    )


@admin_bp.route("/setup/collectors/finish", methods=["GET", "POST"])
@require_api_key
@require_admin
def setup_collectors_finish():
    """Final step — review and (optionally) run all configured collectors.

    This route is both the review page (GET) and the 'Finish' action (POST
    via the same page; 'run all' is triggered by separate per-collector API
    calls from JS so this page simply displays current state).
    """
    from app.services.collector_status import get_overview

    overview = get_overview()
    return render_template(
        "admin/setup_collectors_finish.html",
        overview=overview,
    )
