"""Public trust portal routes — client-facing compliance status."""

from flask import Blueprint, render_template, current_app

from app.models import db, Control, Policy, TestRecord

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
        company_name=current_app.config["PORTAL_COMPANY_NAME"],
        brand_name=current_app.config["PORTAL_BRAND_NAME"],
        contact_email=current_app.config["PORTAL_CONTACT_EMAIL"],
        total_controls=len(controls),
        total_policies=len(policies),
        compliance_score=compliance_score,
        categories=categories,
    )


@portal_bp.route("/policies")
def policies():
    """List all approved policies."""
    approved_policies = Policy.query.filter_by(status="approved").order_by(Policy.category, Policy.title).all()
    return render_template(
        "portal/policies.html",
        policies=approved_policies,
        brand_name=current_app.config["PORTAL_BRAND_NAME"],
    )


@portal_bp.route("/controls")
def controls():
    """List all controls grouped by TSC category."""
    all_controls = Control.query.order_by(Control.category, Control.name).all()
    grouped = {}
    for control in all_controls:
        grouped.setdefault(control.category, []).append(control)
    return render_template(
        "portal/controls.html",
        grouped_controls=grouped,
        brand_name=current_app.config["PORTAL_BRAND_NAME"],
    )


@portal_bp.route("/status")
def status():
    """Detailed compliance status by category."""
    categories = {}
    for category in ["security", "availability", "confidentiality", "privacy", "processing_integrity"]:
        controls = Control.query.filter_by(category=category).all()
        control_data = []
        for control in controls:
            tests = TestRecord.query.filter_by(control_id=control.id).all()
            control_data.append({
                "control": control,
                "tests": tests,
                "passed": sum(1 for t in tests if t.status == "passed"),
                "total": len(tests),
            })
        categories[category] = control_data
    return render_template(
        "portal/status.html",
        categories=categories,
        brand_name=current_app.config["PORTAL_BRAND_NAME"],
    )
