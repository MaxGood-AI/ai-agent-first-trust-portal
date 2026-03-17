"""Admin routes for managing compliance artifacts."""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session

from app.models import db, Control, Policy, TestRecord, Evidence, TeamMember
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
