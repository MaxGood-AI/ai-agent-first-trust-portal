"""Tests for collector_config / collector_run / collector_check_result models."""

import uuid

import pytest

from app import create_app
from app.config import TestConfig
from app.models import (
    CollectorCheckResult,
    CollectorConfig,
    CollectorRun,
    db,
)


@pytest.fixture
def app_ctx():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def _make_config(name="aws", **overrides):
    defaults = {
        "id": str(uuid.uuid4()),
        "name": name,
        "enabled": False,
        "credential_mode": "task_role",
    }
    defaults.update(overrides)
    return CollectorConfig(**defaults)


def test_create_collector_config(app_ctx):
    config = _make_config()
    db.session.add(config)
    db.session.commit()

    fetched = CollectorConfig.query.filter_by(name="aws").one()
    assert fetched.id == config.id
    assert fetched.enabled is False
    assert fetched.credential_mode == "task_role"
    assert fetched.encrypted_credentials is None


def test_collector_config_name_unique(app_ctx):
    db.session.add(_make_config(name="aws"))
    db.session.commit()
    db.session.add(_make_config(name="aws"))
    with pytest.raises(Exception):
        db.session.commit()


def test_collector_config_stores_json_config(app_ctx):
    config = _make_config()
    config.config = {"regions": ["ca-central-1", "us-east-1"], "filters": {}}
    db.session.add(config)
    db.session.commit()

    fetched = CollectorConfig.query.filter_by(name="aws").one()
    assert fetched.config["regions"] == ["ca-central-1", "us-east-1"]


def test_collector_config_stores_permission_check_result(app_ctx):
    config = _make_config()
    config.permission_check_result = {
        "all_passed": True,
        "results": [{"action": "sts:GetCallerIdentity", "status": "pass"}],
    }
    db.session.add(config)
    db.session.commit()

    fetched = CollectorConfig.query.filter_by(name="aws").one()
    assert fetched.permission_check_result["all_passed"] is True


def test_create_collector_run(app_ctx):
    config = _make_config()
    db.session.add(config)
    db.session.commit()

    run = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        trigger_type="manual",
        status="running",
    )
    db.session.add(run)
    db.session.commit()

    assert run.id is not None
    assert run.started_at is not None
    assert run.evidence_count == 0
    assert run.check_pass_count == 0
    assert run.check_fail_count == 0


def test_run_backref_from_config(app_ctx):
    config = _make_config()
    db.session.add(config)
    db.session.commit()

    r1 = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        trigger_type="manual",
        status="success",
    )
    r2 = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        trigger_type="scheduled",
        status="success",
    )
    db.session.add_all([r1, r2])
    db.session.commit()

    assert config.runs.count() == 2


def test_run_cascade_delete(app_ctx):
    config = _make_config()
    db.session.add(config)
    db.session.commit()

    run = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        trigger_type="manual",
        status="success",
    )
    db.session.add(run)
    db.session.commit()

    db.session.delete(config)
    db.session.commit()

    assert CollectorRun.query.count() == 0


def test_create_check_result(app_ctx):
    config = _make_config()
    db.session.add(config)
    db.session.commit()

    run = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        trigger_type="manual",
        status="running",
    )
    db.session.add(run)
    db.session.commit()

    check = CollectorCheckResult(
        id=str(uuid.uuid4()),
        collector_run_id=run.id,
        check_name="iam_mfa",
        status="pass",
        message="MFA enforced for all IAM users",
        detail={"user_count": 4, "mfa_missing": 0},
    )
    db.session.add(check)
    db.session.commit()

    assert run.check_results.count() == 1
    fetched = run.check_results.first()
    assert fetched.check_name == "iam_mfa"
    assert fetched.status == "pass"
    assert fetched.detail["user_count"] == 4


def test_check_result_cascade_delete(app_ctx):
    config = _make_config()
    db.session.add(config)
    db.session.commit()
    run = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        trigger_type="manual",
        status="running",
    )
    db.session.add(run)
    db.session.commit()
    check = CollectorCheckResult(
        id=str(uuid.uuid4()),
        collector_run_id=run.id,
        check_name="x",
        status="pass",
    )
    db.session.add(check)
    db.session.commit()

    db.session.delete(run)
    db.session.commit()
    assert CollectorCheckResult.query.count() == 0
