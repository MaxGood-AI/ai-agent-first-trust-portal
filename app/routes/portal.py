"""Public trust portal routes — client-facing compliance status.

Each page belongs to a public section (``settings_service.PUBLIC_SECTIONS``);
a page whose section is not published answers 404. By default every section
except the risk register is published. Control names appear only while the
``controls`` section is published: without it, ``/status`` shows each
category's totals and a policy page lists no linked controls.
"""

import functools
import logging
import os

from flask import Blueprint, render_template, abort, redirect

from app.models import db, Control, System, Vendor, Policy, TestRecord, RiskRegister
from app.security import is_http_url, render_markdown

logger = logging.getLogger(__name__)

portal_bp = Blueprint("portal", __name__)


def public_section(key):
    """Decorator: the page answers 404 unless the public section ``key`` is published."""
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            from app.services.settings_service import section_enabled

            if not section_enabled(key):
                abort(404)
            return view(*args, **kwargs)
        return wrapped
    return decorator


@portal_bp.route("/")
@public_section("overview")
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
        cat_total = (TestRecord.query.filter(TestRecord.control_id.in_(cat_control_ids)).count()
                     if cat_control_ids else 0)
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
@public_section("policies")
def policies():
    """List all approved policies."""
    approved_policies = Policy.query.filter_by(status="approved").order_by(Policy.category, Policy.title).all()
    return render_template("portal/policies.html", policies=approved_policies)


@portal_bp.route("/policies/<policy_id>")
@public_section("policies")
def policy_detail(policy_id):
    """Display a single approved policy, rendered from the current version
    synced from the governance git source. A policy whose synced file was
    deleted from the repository is shown as retired, with no document. Its
    linked controls are listed only while the controls section is published."""
    from app.services.settings_service import section_enabled

    policy = db.session.get(Policy, policy_id)
    if not policy or policy.status != "approved":
        abort(404)

    from app.services.governance_docs import policy_document_state

    document_state, document = policy_document_state(policy)
    html_content = render_markdown(document.body) if document else None
    linked_controls = list(policy.controls) if section_enabled("controls") else []
    return render_template("portal/policy_detail.html", policy=policy, html_content=html_content,
                           document=document, document_state=document_state,
                           linked_controls=linked_controls)


@portal_bp.route("/controls")
@public_section("controls")
def controls():
    """List all controls grouped by TSC category."""
    all_controls = Control.query.order_by(Control.category, Control.name).all()
    grouped = {}
    for control in all_controls:
        grouped.setdefault(control.category, []).append(control)
    return render_template("portal/controls.html", grouped_controls=grouped)


@portal_bp.route("/status")
@public_section("status")
def status():
    """Detailed compliance status by category: per control while the controls
    section is published, otherwise category totals only (no control names)."""
    from app.services.settings_service import section_enabled

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
    return render_template("portal/status.html", categories=categories,
                           show_controls=section_enabled("controls"))


@portal_bp.route("/controls/<control_id>")
@public_section("controls")
def control_detail(control_id):
    """Display a single control with its tests and its linked approved policies
    (listed only while the policies section is published)."""
    from app.services.settings_service import section_enabled

    control = db.session.get(Control, control_id)
    if not control:
        abort(404)

    tests = TestRecord.query.filter_by(control_id=control.id).all()
    linked_policies = []
    if section_enabled("policies"):
        linked_policies = sorted((p for p in control.policies if p.status == "approved"),
                                 key=lambda p: (p.title or "").lower())
    return render_template("portal/control_detail.html", control=control, tests=tests,
                           linked_policies=linked_policies)


@portal_bp.route("/systems")
@public_section("systems")
def systems():
    """List all systems in the inventory."""
    all_systems = System.query.order_by(System.name).all()
    return render_template("portal/systems.html", systems=all_systems)


@portal_bp.route("/vendors")
@public_section("vendors")
def vendors():
    """List all vendors."""
    all_vendors = Vendor.query.order_by(Vendor.name).all()
    return render_template("portal/vendors.html", vendors=all_vendors)


@portal_bp.route("/risks")
@public_section("risks")
def risks():
    """List risk register entries (private unless an admin publishes the section)."""
    all_risks = RiskRegister.query.order_by(RiskRegister.risk_score.desc().nullslast()).all()
    return render_template("portal/risks.html", risks=all_risks)


def _default_markdown(name):
    path = os.path.join(os.path.dirname(__file__), "..", "templates", "portal", name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()


@portal_bp.route("/legal")
@public_section("legal")
def legal():
    """Privacy policy, terms of use, and accessibility statement."""
    from app.services.settings_service import get_portal_settings
    settings = get_portal_settings()

    if is_http_url(settings.get("legal_external_url")):
        return redirect(settings["legal_external_url"])

    content_md = settings.get("legal_content_md") or _default_markdown("legal_default.md")
    return render_template("portal/legal.html", content=render_markdown(content_md))


@portal_bp.route("/ai-transparency")
@public_section("ai_transparency")
def ai_transparency():
    """AI-driven compliance transparency statement."""
    from app.services.settings_service import get_portal_settings
    settings = get_portal_settings()

    content_md = settings.get("ai_transparency_md") or _default_markdown("ai_transparency_default.md")
    return render_template("portal/ai_transparency.html", content=render_markdown(content_md))
