"""Collector runs decide the result of the automated tests their checks name."""

import uuid

import pytest

from app import create_app
from app.config import TestConfig
from app.models import (
    CollectorConfig, CollectorRun, Control, Evidence, TestRecord, db,
)
from app.services import compliance_engine, team_service
from app.services.collector_executor import _resolve_test_record, execute_run
from app.services.test_execution import apply_outcome
from collectors.base import BaseCollector, CheckResult


@pytest.fixture
def app_ctx(monkeypatch):
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def _control():
    control = Control(id=str(uuid.uuid4()), name="CC6.1", category="security")
    db.session.add(control)
    db.session.flush()
    return control


def _test(name, test_type="auto_assessment", status="pending", control=None, record_id=None):
    control = control or _control()
    record = TestRecord(id=record_id or str(uuid.uuid4()), control_id=control.id, name=name,
                        test_type=test_type, status=status, evidence_status="missing")
    db.session.add(record)
    db.session.commit()
    return record


def _run_with(monkeypatch, results, member_id=None):
    """Execute a collector run whose checks are ``results``."""

    class FakeCollector(BaseCollector):
        name = "fake"

        def run(self):
            return results

    monkeypatch.setattr("app.services.collector_executor.get_collector_class",
                        lambda name: FakeCollector)
    config = CollectorConfig(id=str(uuid.uuid4()), name="fake", enabled=True, credential_mode="none")
    db.session.add(config)
    db.session.commit()
    run = CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id,
                       trigger_type="manual", status="running",
                       triggered_by_team_member_id=member_id)
    db.session.add(run)
    db.session.commit()
    execute_run(run)
    return run


def _check(name, status, test, message=None, evidence=True):
    return CheckResult(check_name=name, status=status, target_test_name=test,
                       message=message or f"{name} {status}",
                       evidence_description=f"evidence for {name}" if evidence else None)


def test_passing_checks_record_success(app_ctx, monkeypatch):
    record = _test("Backup enabled")
    run = _run_with(monkeypatch, [_check("a", "pass", "Backup enabled"),
                                  _check("b", "pass", "Backup enabled")])

    db.session.refresh(record)
    assert (record.status, record.execution_outcome, record.execution_status) == (
        "passed", "success", "completed")
    assert record.last_executed_at is not None
    assert record.evidence_status == "submitted"
    assert "all 2 check(s) passed" in record.finding
    assert run.id in record.comment


def test_any_failing_check_records_failure_with_summary(app_ctx, monkeypatch):
    record = _test("S3 versioning")
    _run_with(monkeypatch, [_check("a", "pass", "S3 versioning"),
                            _check("b", "fail", "S3 versioning", message="bucket x unversioned"),
                            _check("c", "fail", "S3 versioning", message="bucket y unversioned")])

    db.session.refresh(record)
    assert (record.status, record.execution_outcome) == ("failed", "failure")
    assert "2 of 3 check(s) failed" in record.finding
    assert "bucket x unversioned" in record.finding and "bucket y unversioned" in record.finding


def test_failure_summary_lists_five_and_counts_the_rest(app_ctx, monkeypatch):
    record = _test("S3 versioning")
    _run_with(monkeypatch, [_check(f"c{i}", "fail", "S3 versioning", message=f"bucket {i}")
                            for i in range(8)])

    db.session.refresh(record)
    assert "bucket 4" in record.finding and "bucket 5" not in record.finding
    assert "and 3 more" in record.finding


def test_only_error_or_skipped_checks_leave_the_test_untouched(app_ctx, monkeypatch):
    record = _test("CloudTrail enabled")
    _run_with(monkeypatch, [_check("a", "error", "CloudTrail enabled"),
                            _check("b", "skipped", "CloudTrail enabled")])

    db.session.refresh(record)
    assert (record.status, record.execution_outcome, record.last_executed_at) == ("pending", None, None)
    assert record.evidence_status == "missing"


def test_error_check_beside_a_pass_still_records_success(app_ctx, monkeypatch):
    record = _test("CloudTrail enabled")
    _run_with(monkeypatch, [_check("a", "pass", "CloudTrail enabled"),
                            _check("b", "error", "CloudTrail enabled")])

    db.session.refresh(record)
    assert record.status == "passed"


def test_self_assessment_gets_evidence_but_no_outcome(app_ctx, monkeypatch):
    record = _test("Multi-factor authentication enabled for all users", test_type="self_assessment")
    _run_with(monkeypatch, [_check("a", "fail", "Multi-factor authentication enabled for all users")])

    db.session.refresh(record)
    assert (record.status, record.execution_outcome, record.last_executed_at) == ("pending", None, None)
    assert Evidence.query.filter_by(test_record_id=record.id).count() == 1


def test_not_applicable_test_is_never_changed(app_ctx, monkeypatch):
    record = _test("Backup enabled", status="not_applicable")
    _run_with(monkeypatch, [_check("a", "fail", "Backup enabled")])

    db.session.refresh(record)
    assert record.status == "not_applicable"


def test_shared_name_resolves_to_the_auto_assessment_record(app_ctx):
    control = _control()
    _test("Backup enabled", test_type="self_assessment", control=control, record_id="00000000-0000-0000-0000-000000000001")
    auto_high = _test("Backup enabled", control=control, record_id="00000000-0000-0000-0000-000000000009")
    _test("Backup enabled", control=control, record_id="00000000-0000-0000-0000-000000000005")

    assert _resolve_test_record("Backup enabled").id == "00000000-0000-0000-0000-000000000005"
    assert auto_high.id > "00000000-0000-0000-0000-000000000005"


def test_name_shared_by_several_self_assessments_is_ambiguous(app_ctx):
    name = "Multi-factor authentication enabled for all users"
    _test(name, test_type="self_assessment", record_id="00000000-0000-0000-0000-000000000001")
    _test(name, test_type="self_assessment", record_id="00000000-0000-0000-0000-000000000002")

    assert _resolve_test_record(name) is None
    assert _resolve_test_record(name.upper()) is None


def test_name_held_by_one_self_assessment_resolves(app_ctx):
    name = "Multi-factor authentication enabled for all users"
    only = _test(name, test_type="self_assessment")

    assert _resolve_test_record(name).id == only.id
    assert _resolve_test_record(name.upper()).id == only.id


def test_auto_assessment_wins_among_several_self_assessments(app_ctx):
    name = "Multi-factor authentication enabled for all users"
    _test(name, test_type="self_assessment", record_id="00000000-0000-0000-0000-000000000001")
    auto = _test(name, record_id="00000000-0000-0000-0000-000000000009")
    _test(name, test_type="self_assessment", record_id="00000000-0000-0000-0000-000000000002")

    assert _resolve_test_record(name).id == auto.id
    assert _resolve_test_record(name.upper()).id == auto.id


def test_ambiguous_name_creates_no_evidence(app_ctx, monkeypatch):
    name = "Multi-factor authentication enabled for all users"
    first = _test(name, test_type="self_assessment")
    second = _test(name, test_type="self_assessment")
    _run_with(monkeypatch, [_check("a", "fail", name)])

    assert Evidence.query.filter(Evidence.test_record_id.in_([first.id, second.id])).count() == 0


def test_outcome_lands_on_auto_record_when_names_collide(app_ctx, monkeypatch):
    control = _control()
    selfa = _test("Backup enabled", test_type="self_assessment", control=control,
                  record_id="00000000-0000-0000-0000-000000000001")
    auto = _test("Backup enabled", control=control, record_id="00000000-0000-0000-0000-000000000009")
    _run_with(monkeypatch, [_check("a", "pass", "Backup enabled")])

    db.session.refresh(selfa)
    db.session.refresh(auto)
    assert (selfa.status, auto.status) == ("pending", "passed")


def test_run_triggered_by_a_member_attributes_the_write(app_ctx, monkeypatch):
    member = team_service.create_member("Runner", "runner@example.com", "human")
    record = _test("Backup enabled")
    _run_with(monkeypatch, [_check("a", "pass", "Backup enabled")], member_id=member.id)

    from flask import g
    assert getattr(g, "current_team_member", None) is None  # restored after the run
    db.session.refresh(record)
    assert record.status == "passed"


def test_apply_outcome_rejects_unknown_outcome(app_ctx):
    with pytest.raises(ValueError):
        apply_outcome(_test("x"), "maybe")


def test_apply_outcome_keeps_text_when_not_given(app_ctx):
    record = _test("x")
    record.finding = "kept"
    apply_outcome(record, "failure")
    assert (record.finding, record.status) == ("kept", "failed")


def test_not_applicable_tests_leave_the_score_denominator(app_ctx):
    control = _control()
    _test("one", status="passed", control=control)
    _test("two", status="failed", control=control)
    _test("three", status="not_applicable", control=control)

    assert compliance_engine.score_counts() == (1, 2)
    assert compliance_engine.calculate_overall_score() == 50.0
    assert compliance_engine.calculate_category_score("security") == 50.0
    assert compliance_engine.get_compliance_summary()["total_tests"] == 3


def test_public_page_and_score_api_exclude_not_applicable(app_ctx):
    control = _control()
    _test("one", status="passed", control=control)
    _test("two", status="failed", control=control)
    _test("three", status="not_applicable", control=control)
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)

    page = app_ctx.test_client().get("/")
    assert page.status_code == 200
    assert b"50%" in page.data
    assert b"1/2 tests passing" in page.data

    body = app_ctx.test_client().get(
        "/api/compliance-score", headers={"X-API-Key": admin.issued_api_key}).get_json()
    assert body["overall_score"] == 50.0
    assert body["categories"]["security"]["score"] == 50.0
    assert (body["total_tests"], body["passed_tests"], body["not_applicable_tests"]) == (2, 1, 1)
