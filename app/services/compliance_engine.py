"""Compliance scoring and gap analysis engine."""

from app.models import db, Control, TestRecord


def calculate_overall_score():
    """Calculate the overall compliance score as a percentage."""
    total = TestRecord.query.count()
    if total == 0:
        return 0.0
    passed = TestRecord.query.filter_by(status="passed").count()
    return round(passed / total * 100, 1)


def calculate_category_score(category):
    """Calculate compliance score for a specific TSC category."""
    controls = Control.query.filter_by(category=category).all()
    control_ids = [c.id for c in controls]
    if not control_ids:
        return 0.0
    total = TestRecord.query.filter(TestRecord.control_id.in_(control_ids)).count()
    if total == 0:
        return 0.0
    passed = TestRecord.query.filter(
        TestRecord.control_id.in_(control_ids),
        TestRecord.status == "passed"
    ).count()
    return round(passed / total * 100, 1)


def get_evidence_gaps():
    """Return all tests with missing, outdated, or due-soon evidence."""
    return TestRecord.query.filter(
        TestRecord.evidence_status.in_(["missing", "outdated", "due_soon"])
    ).order_by(TestRecord.evidence_status, TestRecord.due_at).all()


def get_compliance_summary():
    """Return a full compliance summary dict."""
    categories = ["security", "availability", "confidentiality", "privacy", "processing_integrity"]
    return {
        "overall_score": calculate_overall_score(),
        "total_controls": Control.query.count(),
        "total_tests": TestRecord.query.count(),
        "evidence_gaps": TestRecord.query.filter(
            TestRecord.evidence_status.in_(["missing", "outdated", "due_soon"])
        ).count(),
        "categories": {
            cat: calculate_category_score(cat) for cat in categories
        },
    }
