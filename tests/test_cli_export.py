"""Tests for the CLI export command (#654)."""

import json
import os
import tempfile

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db, Control, TestRecord, System, Policy, Vendor, Evidence, RiskRegister


@pytest.fixture
def app(tmp_path):
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def _seed_data():
    ctrl = Control(id="ctrl-exp", name="Export Control", category="security",
                   source_category="Cloud Infrastructure", control_id_short="SEC-1")
    db.session.add(ctrl)
    tr = TestRecord(id="tr-exp", control_id="ctrl-exp", name="Export Test",
                    status="passed", evidence_status="submitted")
    db.session.add(tr)
    sys = System(id="sys-exp", name="RDS", system_type=["infrastructure"])
    db.session.add(sys)
    pol = Policy(id="pol-exp", title="Export Policy", category="security", status="approved")
    db.session.add(pol)
    vnd = Vendor(id="vnd-exp", name="AWS")
    db.session.add(vnd)
    ev = Evidence(id="ev-exp", test_record_id="tr-exp", evidence_type="automated",
                  description="Scan results")
    db.session.add(ev)
    risk = RiskRegister(id="risk-exp", name="Export Risk", likelihood=3, impact=4)
    db.session.add(risk)
    db.session.commit()


def test_export_controls_json(app, tmp_path):
    with app.app_context():
        _seed_data()
        from cli.export import export_all
        export_all(str(tmp_path))

    data = json.loads((tmp_path / "controls.json").read_text())
    assert len(data) == 1
    assert data[0]["tsc_category"] == "security"
    assert data[0]["category"] == "Cloud Infrastructure"


def test_export_tests_reverse_value_maps(app, tmp_path):
    with app.app_context():
        _seed_data()
        from cli.export import export_all
        export_all(str(tmp_path))

    data = json.loads((tmp_path / "tests.json").read_text())
    assert data[0]["status"] == "success"
    assert data[0]["evidence_status"] == "up_to_date"


def test_export_systems_reverse_field_maps(app, tmp_path):
    with app.app_context():
        _seed_data()
        from cli.export import export_all
        export_all(str(tmp_path))

    data = json.loads((tmp_path / "systems.json").read_text())
    assert "type" in data[0]
    assert "system_type" not in data[0]
    assert data[0]["type"] == ["infrastructure"]


def test_export_evidence_creates_subdirectory(app, tmp_path):
    with app.app_context():
        _seed_data()
        from cli.export import export_all
        export_all(str(tmp_path))

    assert (tmp_path / "evidence" / "evidence-index.json").exists()
    data = json.loads((tmp_path / "evidence" / "evidence-index.json").read_text())
    assert len(data) == 1


def test_export_deterministic_output(app, tmp_path):
    with app.app_context():
        _seed_data()
        from cli.export import export_all
        dir1 = tmp_path / "run1"
        dir2 = tmp_path / "run2"
        export_all(str(dir1))
        export_all(str(dir2))

    for filename in ["controls.json", "systems.json", "tests.json"]:
        content1 = (dir1 / filename).read_text()
        content2 = (dir2 / filename).read_text()
        assert content1 == content2


def test_export_skips_internal_timestamps(app, tmp_path):
    with app.app_context():
        _seed_data()
        from cli.export import export_all
        export_all(str(tmp_path))

    data = json.loads((tmp_path / "controls.json").read_text())
    assert "created_at" not in data[0]
    assert "updated_at" not in data[0]


def test_export_merges_other_data(app, tmp_path):
    with app.app_context():
        ctrl = Control(id="ctrl-od", name="OD Control", category="security",
                       other_data={"custom_field": "custom_value"})
        db.session.add(ctrl)
        db.session.commit()
        from cli.export import export_all
        export_all(str(tmp_path))

    data = json.loads((tmp_path / "controls.json").read_text())
    od_ctrl = next(d for d in data if d["id"] == "ctrl-od")
    assert od_ctrl["custom_field"] == "custom_value"


def test_export_empty_tables(app, tmp_path):
    with app.app_context():
        from cli.export import export_all
        export_all(str(tmp_path))

    for filename in ["controls.json", "systems.json", "tests.json",
                     "policy-index.json", "vendors.json", "risk-register.json"]:
        data = json.loads((tmp_path / filename).read_text())
        assert data == []


def test_export_all_files_created(app, tmp_path):
    with app.app_context():
        _seed_data()
        from cli.export import export_all
        result = export_all(str(tmp_path))

    assert result["status"] == "success"
    expected_files = [
        "controls.json", "systems.json", "tests.json",
        "policy-index.json", "vendors.json", "risk-register.json",
    ]
    for f in expected_files:
        assert (tmp_path / f).exists(), f"Missing: {f}"
    assert (tmp_path / "evidence" / "evidence-index.json").exists()
