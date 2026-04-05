"""Public trust portal routes — client-facing compliance status."""

import logging
import os

import markdown
from flask import Blueprint, render_template, current_app, abort, redirect
from markupsafe import Markup

from app.models import db, Control, System, Vendor, Policy, TestRecord, RiskRegister

logger = logging.getLogger(__name__)

portal_bp = Blueprint("portal", __name__)


@portal_bp.route("/")
def index():
    """Trust portal landing page showing overall compliance posture."""
    controls = Control.query.all()
    policies = Policy.query.filter_by(status="approved").all()

    total_tests = TestRecord.query.count()
    passed_tests = TestRecord.query.filter_by(status="passed").count()
    compliance_score = (passed_tests / total_tests * 100) if total_tests > 0 else 0

    categories = {}
    for category in ["security", "availability", "confidentiality", "privacy", "processing_integrity"]:
        cat_controls = Control.query.filter_by(category=category).all()
        cat_control_ids = [c.id for c in cat_controls]
        cat_total = TestRecord.query.filter(TestRecord.control_id.in_(cat_control_ids)).count() if cat_control_ids else 0
        cat_passed = TestRecord.query.filter(
            TestRecord.control_id.in_(cat_control_ids),
            TestRecord.status == "passed"
        ).count() if cat_control_ids else 0
        categories[category] = {
            "controls": len(cat_controls),
            "total_tests": cat_total,
            "passed_tests": cat_passed,
            "score": (cat_passed / cat_total * 100) if cat_total > 0 else 0,
        }

    return render_template(
        "portal/index.html",
        total_controls=len(controls),
        total_policies=len(policies),
        compliance_score=compliance_score,
        categories=categories,
    )


@portal_bp.route("/policies")
def policies():
    """List all approved policies."""
    approved_policies = Policy.query.filter_by(status="approved").order_by(Policy.category, Policy.title).all()
    return render_template("portal/policies.html", policies=approved_policies)


@portal_bp.route("/policies/<policy_id>")
def policy_detail(policy_id):
    """Display a single policy with rendered markdown content."""
    policy = db.session.get(Policy, policy_id)
    if not policy:
        abort(404)

    html_content = None
    if policy.file_path:
        policy_dir = current_app.config.get("POLICY_DIR", "")
        if policy_dir:
            full_path = os.path.join(policy_dir, os.path.basename(policy.file_path))
        else:
            full_path = policy.file_path

        if os.path.exists(full_path):
            try:
                import frontmatter
                post = frontmatter.load(full_path)
                html_content = Markup(markdown.markdown(
                    post.content,
                    extensions=["tables", "fenced_code", "toc"],
                ))
            except Exception:
                logger.warning("Could not render policy file: %s", full_path)

    return render_template("portal/policy_detail.html", policy=policy, html_content=html_content)


@portal_bp.route("/controls")
def controls():
    """List all controls grouped by TSC category."""
    all_controls = Control.query.order_by(Control.category, Control.name).all()
    grouped = {}
    for control in all_controls:
        grouped.setdefault(control.category, []).append(control)
    return render_template("portal/controls.html", grouped_controls=grouped)


@portal_bp.route("/status")
def status():
    """Detailed compliance status by category."""
    categories = {}
    for category in ["security", "availability", "confidentiality", "privacy", "processing_integrity"]:
        cat_controls = Control.query.filter_by(category=category).all()
        control_data = []
        for control in cat_controls:
            tests = TestRecord.query.filter_by(control_id=control.id).all()
            control_data.append({
                "control": control,
                "tests": tests,
                "passed": sum(1 for t in tests if t.status == "passed"),
                "total": len(tests),
            })
        categories[category] = control_data
    return render_template("portal/status.html", categories=categories)


@portal_bp.route("/controls/<control_id>")
def control_detail(control_id):
    """Display a single control with its tests and linked policies."""
    control = db.session.get(Control, control_id)
    if not control:
        abort(404)

    tests = TestRecord.query.filter_by(control_id=control.id).all()
    return render_template("portal/control_detail.html", control=control, tests=tests)


@portal_bp.route("/systems")
def systems():
    """List all systems in the inventory."""
    all_systems = System.query.order_by(System.name).all()
    return render_template("portal/systems.html", systems=all_systems)


@portal_bp.route("/vendors")
def vendors():
    """List all vendors."""
    all_vendors = Vendor.query.order_by(Vendor.name).all()
    return render_template("portal/vendors.html", vendors=all_vendors)


@portal_bp.route("/risks")
def risks():
    """List risk register entries."""
    all_risks = RiskRegister.query.order_by(RiskRegister.risk_score.desc().nullslast()).all()
    return render_template("portal/risks.html", risks=all_risks)


@portal_bp.route("/legal")
def legal():
    """Privacy policy, terms of use, and accessibility statement."""
    from app.services.settings_service import get_portal_settings
    settings = get_portal_settings()

    if settings.get("legal_external_url"):
        return redirect(settings["legal_external_url"])

    content_md = settings.get("legal_content_md")

    if not content_md:
        policy_dir = current_app.config.get("POLICY_DIR", "")
        if policy_dir:
            legal_path = os.path.join(policy_dir, "legal.md")
            if os.path.exists(legal_path):
                with open(legal_path) as f:
                    content_md = f.read()

    if not content_md:
        default_path = os.path.join(
            os.path.dirname(__file__), "..", "templates", "portal", "legal_default.md"
        )
        with open(default_path) as f:
            content_md = f.read()

    content_html = Markup(markdown.markdown(
        content_md, extensions=["tables", "fenced_code", "toc"]
    ))
    return render_template("portal/legal.html", content=content_html)


@portal_bp.route("/ai-transparency")
def ai_transparency():
    """AI-driven compliance transparency statement."""
    from app.services.settings_service import get_portal_settings
    settings = get_portal_settings()

    content_md = settings.get("ai_transparency_md")

    if not content_md:
        default_path = os.path.join(
            os.path.dirname(__file__), "..", "templates", "portal", "ai_transparency_default.md"
        )
        with open(default_path) as f:
            content_md = f.read()

    content_html = Markup(markdown.markdown(
        content_md, extensions=["tables", "fenced_code", "toc"]
    ))
    return render_template("portal/ai_transparency.html", content=content_html)
