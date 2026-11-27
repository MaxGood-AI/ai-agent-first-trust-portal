"""Compliance scoring and gap analysis engine.

A score is ``passed / applicable * 100``. A test whose status is
``not_applicable`` does not apply to the organisation, so it counts in
neither the numerator nor the denominator. Every score the portal shows
(public pages, API, admin, client report) is computed here.
"""

from app.models import Control, TestRecord

TSC_CATEGORIES = ["security", "availability", "confidentiality", "privacy", "processing_integrity"]


def _scoped(control_ids=None):
    """Query of the test records in scope (all, or those of ``control_ids``)."""
    query = TestRecord.query
    if control_ids is not None:
        query = query.filter(TestRecord.control_id.in_(control_ids))
    return query


def score_counts(control_ids=None):
    """Return ``(passed, applicable)`` test counts, optionally limited to ``control_ids``.

    ``applicable`` excludes tests whose status is ``not_applicable``.
    """
    query = _scoped(control_ids)
    applicable = query.filter(TestRecord.status != "not_applicable").count()
    passed = query.filter(TestRecord.status == "passed").count()
    return passed, applicable


def percentage(passed, applicable, digits=1):
    """``passed`` as a percentage of ``applicable`` (0.0 when nothing applies)."""
    if applicable == 0:
        return 0.0
    return round(passed / applicable * 100, digits)


def category_counts(category):
    """Return ``(controls, passed, applicable)`` for one TSC category."""
    controls = Control.query.filter_by(category=category).all()
    control_ids = [c.id for c in controls]
    if not control_ids:
        return len(controls), 0, 0
    passed, applicable = score_counts(control_ids)
    return len(controls), passed, applicable


def applicable_tests(tests):
    """The tests of ``tests`` that apply (status other than ``not_applicable``)."""
    return [t for t in tests if t.status != "not_applicable"]


def calculate_overall_score():
    """Calculate the overall compliance score as a percentage."""
    passed, applicable = score_counts()
    return percentage(passed, applicable)


def calculate_category_score(category):
    """Calculate compliance score for a specific TSC category."""
    _, passed, applicable = category_counts(category)
    return percentage(passed, applicable)


def get_evidence_gaps():
    """Return all tests with missing, outdated, or due-soon evidence."""
    return TestRecord.query.filter(
        TestRecord.evidence_status.in_(["missing", "outdated", "due_soon"])
    ).order_by(TestRecord.evidence_status, TestRecord.due_at).all()


def get_compliance_summary():
    """Return a full compliance summary dict."""
    return {
        "overall_score": calculate_overall_score(),
        "total_controls": Control.query.count(),
        "total_tests": TestRecord.query.count(),
        "evidence_gaps": TestRecord.query.filter(
            TestRecord.evidence_status.in_(["missing", "outdated", "due_soon"])
        ).count(),
        "categories": {
            cat: calculate_category_score(cat) for cat in TSC_CATEGORIES
        },
    }
