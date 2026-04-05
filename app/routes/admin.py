"""Admin routes for managing compliance artifacts."""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session

from app.models import db, Control, System, Vendor, Policy, TestRecord, Evidence, RiskRegister, TeamMember
from app.auth import require_api_key, require_admin
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
    total_controls = Control.query.count()
    total_tests = TestRecord.query.count()
    missing_evidence = TestRecord.query.filter_by(evidence_status="missing").count()
    outdated_evidence = TestRecord.query.filter_by(evidence_status="outdated").count()
    total_policies = Policy.query.count()
    approved_policies = Policy.query.filter_by(status="approved").count()
    total_members = TeamMember.query.filter_by(is_active=True).count()

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
    )


@admin_bp.route("/evidence")
@require_api_key
@require_admin
def evidence_management():
    """Evidence management view — shows tests needing evidence."""
    tests_needing_attention = TestRecord.query.filter(
        TestRecord.evidence_status.in_(["missing", "outdated", "due_soon"])
    ).order_by(TestRecord.evidence_status, TestRecord.due_at).all()

    return render_template(
        "admin/evidence.html",
        tests=tests_needing_attention,
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

    if not name or not email:
        flash("Name and email are required.", "error")
        return redirect(url_for("admin.team_management"))

    if role not in ("human", "agent"):
        flash("Role must be 'human' or 'agent'.", "error")
        return redirect(url_for("admin.team_management"))

    member = team_service.create_member(name, email, role, is_compliance_admin=is_admin)
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
