"""Tests for the CLI init command and data loaders."""

import json
import os
import uuid

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db, Control, System, Vendor, TestRecord, Policy, Evidence


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def data_dir(tmp_path):
    """Create a temp data directory with fixture JSON files."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    return tmp_path


def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f)


# --- Controls Loader Tests ---


def test_load_controls(app, data_dir):
    """Load controls and verify tsc_category → category mapping."""
    write_json(data_dir / "controls.json", [
        {
            "id": "ctrl-001",
            "name": "MFA Enforcement",
            "description": "All users must use MFA",
            "category": "Identity and Access Control",
            "tsc_category": "security",
            "state": "adopted",
            "trustcloud_id": "tc-001",
        },
        {
            "id": "ctrl-002",
            "name": "Backup Policy",
            "description": "Regular backups required",
            "category": "Cloud Infrastructure",
            "tsc_category": "availability",
            "state": "adopted",
        },
    ])

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        result = ControlsLoader().load(str(data_dir))

        assert result["inserted"] == 2
        assert result["skipped"] == 0

        c1 = db.session.get(Control, "ctrl-001")
        assert c1.name == "MFA Enforcement"
        assert c1.category == "security"  # tsc_category mapped to category
        assert c1.trustcloud_id == "tc-001"

        c2 = db.session.get(Control, "ctrl-002")
        assert c2.category == "availability"


def test_load_controls_other_data(app, data_dir):
    """Verify unmapped fields are stored in other_data."""
    write_json(data_dir / "controls.json", [{
        "id": "ctrl-003",
        "name": "Host Hardening",
        "tsc_category": "security",
        "category": "Cloud Infrastructure",
        "control_id_short": "INFRA-8",
        "frequency": "annual",
        "maturity_level": 2,
        "group_name": "DevOps",
        "soc2_references": [{"referenceId": "CC6.1", "description": "Logical access"}],
        "owner": {"id": "owner-1", "name": "Alice"},
    }])

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        ControlsLoader().load(str(data_dir))

        c = db.session.get(Control, "ctrl-003")
        assert c.category == "security"
        od = c.other_data
        assert od["category"] == "Cloud Infrastructure"
        assert od["control_id_short"] == "INFRA-8"
        assert od["frequency"] == "annual"
        assert od["maturity_level"] == 2
        assert od["group_name"] == "DevOps"
        assert od["soc2_references"][0]["referenceId"] == "CC6.1"
        assert od["owner"]["name"] == "Alice"


def test_idempotent_rerun(app, data_dir):
    """Loading controls twice produces same row count."""
    write_json(data_dir / "controls.json", [
        {"id": "ctrl-idem", "name": "Idempotent", "tsc_category": "security"},
    ])

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        loader = ControlsLoader()
        r1 = loader.load(str(data_dir))
        assert r1["inserted"] == 1

        r2 = loader.load(str(data_dir))
        assert r2["updated"] == 1
        assert r2["inserted"] == 0
        assert Control.query.count() == 1


def test_idempotent_other_data_update(app, data_dir):
    """Changing a field in JSON and re-running updates other_data."""
    write_json(data_dir / "controls.json", [
        {"id": "ctrl-upd", "name": "Updatable", "tsc_category": "security", "frequency": "annual"},
    ])

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        loader = ControlsLoader()
        loader.load(str(data_dir))
        assert db.session.get(Control, "ctrl-upd").other_data["frequency"] == "annual"

    write_json(data_dir / "controls.json", [
        {"id": "ctrl-upd", "name": "Updatable", "tsc_category": "security", "frequency": "quarterly"},
    ])

    with app.app_context():
        loader.load(str(data_dir))
        assert db.session.get(Control, "ctrl-upd").other_data["frequency"] == "quarterly"


# --- Tests Loader Tests ---


def test_load_tests_with_status_mapping(app, data_dir):
    """Verify all 4 status values map correctly."""
    write_json(data_dir / "controls.json", [
        {"id": "ctrl-t", "name": "Test Control", "tsc_category": "security"},
    ])

    tests = []
    for i, (status, expected) in enumerate([
        ("success", "passed"),
        ("failure", "failed"),
        ("not_run", "pending"),
        ("excluded", "not_applicable"),
    ]):
        tests.append({
            "id": f"test-{i}",
            "control_id": "ctrl-t",
            "name": f"Test {i}",
            "status": status,
            "evidence_status": "missing",
        })

    write_json(data_dir / "tests.json", tests)

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        from cli.loaders.tests import TestsLoader
        ControlsLoader().load(str(data_dir))
        TestsLoader().load(str(data_dir))

        expected_map = {
            "test-0": "passed",
            "test-1": "failed",
            "test-2": "pending",
            "test-3": "not_applicable",
        }
        for tid, expected_status in expected_map.items():
            t = db.session.get(TestRecord, tid)
            assert t.status == expected_status, f"{tid}: expected {expected_status}, got {t.status}"


def test_load_tests_original_status_preserved(app, data_dir):
    """Verify _original_status in other_data."""
    write_json(data_dir / "controls.json", [
        {"id": "ctrl-os", "name": "Control", "tsc_category": "security"},
    ])
    write_json(data_dir / "tests.json", [{
        "id": "test-os",
        "control_id": "ctrl-os",
        "name": "Original Status Test",
        "status": "success",
        "evidence_status": "up_to_date",
    }])

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        from cli.loaders.tests import TestsLoader
        ControlsLoader().load(str(data_dir))
        TestsLoader().load(str(data_dir))

        t = db.session.get(TestRecord, "test-os")
        assert t.status == "passed"
        assert t.evidence_status == "submitted"
        assert t.other_data["_original_status"] == "success"
        assert t.other_data["_original_evidence_status"] == "up_to_date"


def test_load_tests_with_evidence_status_mapping(app, data_dir):
    """Verify all 5 evidence_status values map correctly."""
    write_json(data_dir / "controls.json", [
        {"id": "ctrl-es", "name": "Control", "tsc_category": "security"},
    ])

    tests = []
    for i, (es, expected) in enumerate([
        ("missing", "missing"),
        ("up_to_date", "submitted"),
        ("outdated", "outdated"),
        ("not_required", "submitted"),
        ("due", "due_soon"),
    ]):
        tests.append({
            "id": f"test-es-{i}",
            "control_id": "ctrl-es",
            "name": f"ES Test {i}",
            "status": "not_run",
            "evidence_status": es,
        })

    write_json(data_dir / "tests.json", tests)

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        from cli.loaders.tests import TestsLoader
        ControlsLoader().load(str(data_dir))
        TestsLoader().load(str(data_dir))

        expected_map = {
            "test-es-0": "missing",
            "test-es-1": "submitted",
            "test-es-2": "outdated",
            "test-es-3": "submitted",
            "test-es-4": "due_soon",
        }
        for tid, expected_es in expected_map.items():
            t = db.session.get(TestRecord, tid)
            assert t.evidence_status == expected_es


def test_load_tests_other_data(app, data_dir):
    """Verify unmapped fields in other_data."""
    write_json(data_dir / "controls.json", [
        {"id": "ctrl-tod", "name": "Control", "tsc_category": "security"},
    ])
    write_json(data_dir / "tests.json", [{
        "id": "test-tod",
        "control_id": "ctrl-tod",
        "name": "Test Other Data",
        "status": "success",
        "evidence_status": "missing",
        "test_type": "auto_assessment",
        "execution_outcome": "failure",
        "finding": "Something was wrong",
        "system": {"id": "sys-1", "name": "RDS", "short_name": "rds"},
        "owner": {"id": "owner-1", "name": "Bob"},
        "control_name": "Control",
        "control_id_short": "INFRA-1",
    }])

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        from cli.loaders.tests import TestsLoader
        ControlsLoader().load(str(data_dir))
        TestsLoader().load(str(data_dir))

        t = db.session.get(TestRecord, "test-tod")
        od = t.other_data
        assert od["test_type"] == "auto_assessment"
        assert od["execution_outcome"] == "failure"
        assert od["finding"] == "Something was wrong"
        assert od["system"]["name"] == "RDS"
        assert od["owner"]["name"] == "Bob"


def test_load_tests_missing_control(app, data_dir):
    """Test with bad control_id is skipped."""
    write_json(data_dir / "tests.json", [{
        "id": "test-bad",
        "control_id": "nonexistent-ctrl",
        "name": "Bad Reference",
        "status": "not_run",
        "evidence_status": "missing",
    }])

    with app.app_context():
        from cli.loaders.tests import TestsLoader
        result = TestsLoader().load(str(data_dir))
        assert result["skipped"] == 1
        assert result["inserted"] == 0


# --- Policies Loader Tests ---


def test_load_policies(app, data_dir):
    """Verify date parsing for approved_at/next_review_at."""
    write_json(data_dir / "policy-index.json", [{
        "id": "pol-001",
        "title": "Encryption Policy",
        "category": "confidentiality",
        "version": "1.0",
        "file_path": "../policies/encryption.md",
        "status": "approved",
        "approved_at": "2026-03-25",
        "approved_by": "Admin",
        "next_review_at": "2027-03-25",
        "trustcloud_id": "tc-pol-1",
    }])

    with app.app_context():
        from cli.loaders.policies import PoliciesLoader
        result = PoliciesLoader().load(str(data_dir))
        assert result["inserted"] == 1

        p = db.session.get(Policy, "pol-001")
        assert p.title == "Encryption Policy"
        assert p.category == "confidentiality"
        assert p.approved_at is not None
        assert p.approved_at.year == 2026
        assert p.approved_at.month == 3
        assert p.approved_at.day == 25
        assert p.next_review_at.year == 2027


def test_load_policies_other_data(app, data_dir):
    """Verify unmapped fields in other_data."""
    write_json(data_dir / "policy-index.json", [{
        "id": "pol-od",
        "title": "Test Policy",
        "category": "security",
        "short_name": "POL-1",
        "security_group": "Security Operations",
        "soc2_control_ids": ["ctrl-a", "ctrl-b"],
        "group_name": "Engineering",
        "owner": {"id": None, "name": "Admin"},
        "notes": "Some notes",
    }])

    with app.app_context():
        from cli.loaders.policies import PoliciesLoader
        PoliciesLoader().load(str(data_dir))

        p = db.session.get(Policy, "pol-od")
        od = p.other_data
        assert od["short_name"] == "POL-1"
        assert od["security_group"] == "Security Operations"
        assert od["soc2_control_ids"] == ["ctrl-a", "ctrl-b"]
        assert od["owner"]["name"] == "Admin"
        assert od["notes"] == "Some notes"


# --- Evidence Loader Tests ---


def test_load_evidence_matching_test(app, data_dir):
    """Evidence resolves test_name to test_record_id."""
    # Seed a control and test
    with app.app_context():
        ctrl = Control(id="ctrl-ev", name="Vuln Control", category="security")
        db.session.add(ctrl)
        tr = TestRecord(
            id="test-ev",
            control_id="ctrl-ev",
            name="Vulnerability scanning",
            status="passed",
            evidence_status="submitted",
        )
        db.session.add(tr)
        db.session.commit()

    write_json(data_dir / "evidence" / "evidence-index.json", [{
        "test_name": "Vulnerability scanning",
        "evidence_type": "automated",
        "description": "Layer 1 scan",
        "url": None,
        "file_path": "layer1-scan.json",
        "collected_at": "2026-03-26T10:59:16+00:00",
        "collector_name": "scanner-layer1",
    }])

    with app.app_context():
        from cli.loaders.evidence import EvidenceLoader
        result = EvidenceLoader().load(str(data_dir))
        assert result["inserted"] == 1

        ev = Evidence.query.first()
        assert ev.test_record_id == "test-ev"
        assert ev.evidence_type == "automated"
        assert ev.collector_name == "scanner-layer1"
        assert ev.other_data["test_name"] == "Vulnerability scanning"


def test_load_evidence_no_match(app, data_dir):
    """Evidence skipped when no test matches."""
    write_json(data_dir / "evidence" / "evidence-index.json", [{
        "test_name": "Nonexistent test",
        "evidence_type": "automated",
        "description": "No match",
        "collected_at": "2026-03-26T00:00:00+00:00",
        "collector_name": "test",
    }])

    with app.app_context():
        from cli.loaders.evidence import EvidenceLoader
        result = EvidenceLoader().load(str(data_dir))
        assert result["skipped"] == 1
        assert result["inserted"] == 0


def test_load_evidence_deterministic_ids(app, data_dir):
    """Same data produces same UUIDs across runs."""
    with app.app_context():
        ctrl = Control(id="ctrl-det", name="Det Control", category="security")
        db.session.add(ctrl)
        tr = TestRecord(
            id="test-det", control_id="ctrl-det", name="Det Test",
            status="passed", evidence_status="submitted",
        )
        db.session.add(tr)
        db.session.commit()

    evidence_data = [{
        "test_name": "Det Test",
        "evidence_type": "automated",
        "description": "Deterministic",
        "file_path": "det-scan.json",
        "collected_at": "2026-01-01T00:00:00+00:00",
        "collector_name": "det",
    }]
    write_json(data_dir / "evidence" / "evidence-index.json", evidence_data)

    with app.app_context():
        from cli.loaders.evidence import EvidenceLoader
        loader = EvidenceLoader()
        loader.load(str(data_dir))
        ev1 = Evidence.query.first()
        id1 = ev1.id

        # Run again — should produce same ID
        loader.load(str(data_dir))
        assert Evidence.query.count() == 1
        assert Evidence.query.first().id == id1


def test_load_evidence_other_data(app, data_dir):
    """Verify test_name preserved in other_data."""
    with app.app_context():
        ctrl = Control(id="ctrl-eod", name="C", category="security")
        db.session.add(ctrl)
        tr = TestRecord(
            id="test-eod", control_id="ctrl-eod", name="Evidence OD Test",
            status="passed", evidence_status="submitted",
        )
        db.session.add(tr)
        db.session.commit()

    write_json(data_dir / "evidence" / "evidence-index.json", [{
        "test_name": "Evidence OD Test",
        "evidence_type": "automated",
        "description": "test",
        "collected_at": "2026-01-01T00:00:00+00:00",
        "collector_name": "test",
        "extra_field": "should be in other_data",
    }])

    with app.app_context():
        from cli.loaders.evidence import EvidenceLoader
        EvidenceLoader().load(str(data_dir))
        ev = Evidence.query.first()
        assert ev.other_data["test_name"] == "Evidence OD Test"
        assert ev.other_data["extra_field"] == "should be in other_data"


# --- Systems Loader Tests ---


def test_load_systems(app, data_dir):
    """Load systems and verify field mapping including type → system_type."""
    write_json(data_dir / "systems.json", [
        {
            "id": "sys-001",
            "name": "AWS Code Commit",
            "short_name": "aws-code-commit",
            "purpose": "Source Control",
            "risk_score": 0.0,
            "type": ["application"],
            "group_name": "Engineering",
            "provider": "AWS",
            "data_classifications": ["company_restricted"],
            "trustcloud_id": "tc-sys-1",
        },
        {
            "id": "sys-002",
            "name": "RDS",
            "short_name": "rds",
            "purpose": "Data Store",
            "risk_score": 55.56,
            "type": ["infrastructure"],
            "provider": "AWS",
            "data_classifications": ["customer_confidential", "company_restricted"],
        },
    ])

    with app.app_context():
        from cli.loaders.systems import SystemsLoader
        result = SystemsLoader().load(str(data_dir))

        assert result["inserted"] == 2

        s1 = db.session.get(System, "sys-001")
        assert s1.name == "AWS Code Commit"
        assert s1.short_name == "aws-code-commit"
        assert s1.purpose == "Source Control"
        assert s1.risk_score == 0.0
        assert s1.system_type == ["application"]  # type → system_type
        assert s1.provider == "AWS"
        assert s1.data_classifications == ["company_restricted"]
        assert s1.group_name == "Engineering"

        s2 = db.session.get(System, "sys-002")
        assert s2.risk_score == 55.56
        assert s2.data_classifications == ["customer_confidential", "company_restricted"]


def test_load_systems_other_data(app, data_dir):
    """Verify owner stored in other_data."""
    write_json(data_dir / "systems.json", [{
        "id": "sys-od",
        "name": "Test System",
        "type": ["application"],
        "owner": {"id": "owner-1", "name": "Alice"},
    }])

    with app.app_context():
        from cli.loaders.systems import SystemsLoader
        SystemsLoader().load(str(data_dir))

        s = db.session.get(System, "sys-od")
        assert s.other_data["owner"]["name"] == "Alice"


def test_load_tests_with_system_id(app, data_dir):
    """Tests with system references get system_id FK populated."""
    write_json(data_dir / "systems.json", [
        {"id": "sys-fk", "name": "RDS", "type": ["infrastructure"]},
    ])
    write_json(data_dir / "controls.json", [
        {"id": "ctrl-fk", "name": "Control", "tsc_category": "security"},
    ])
    write_json(data_dir / "tests.json", [{
        "id": "test-fk",
        "control_id": "ctrl-fk",
        "name": "RDS Encryption",
        "status": "success",
        "evidence_status": "missing",
        "system": {"id": "sys-fk", "name": "RDS", "short_name": "rds"},
    }])

    with app.app_context():
        from cli.loaders.systems import SystemsLoader
        from cli.loaders.controls import ControlsLoader
        from cli.loaders.tests import TestsLoader
        SystemsLoader().load(str(data_dir))
        ControlsLoader().load(str(data_dir))
        TestsLoader().load(str(data_dir))

        t = db.session.get(TestRecord, "test-fk")
        assert t.system_id == "sys-fk"
        assert t.system.name == "RDS"
        # The full system object should be in other_data too
        assert t.other_data["system"]["name"] == "RDS"


def test_load_tests_without_system(app, data_dir):
    """Tests with null system load fine (system_id = None)."""
    write_json(data_dir / "controls.json", [
        {"id": "ctrl-ns", "name": "Control", "tsc_category": "security"},
    ])
    write_json(data_dir / "tests.json", [{
        "id": "test-ns",
        "control_id": "ctrl-ns",
        "name": "No System Test",
        "status": "not_run",
        "evidence_status": "missing",
    }])

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        from cli.loaders.tests import TestsLoader
        ControlsLoader().load(str(data_dir))
        TestsLoader().load(str(data_dir))

        t = db.session.get(TestRecord, "test-ns")
        assert t.system_id is None


# --- Vendors Loader Tests ---


def test_load_vendors(app, data_dir):
    """Load vendors and verify all fields."""
    write_json(data_dir / "vendors.json", [
        {
            "id": "vnd-001",
            "name": "Amazon Web Services",
            "status": "active",
            "is_subprocessor": True,
            "classification": ["customer_confidential"],
            "locations": [{"label": "Canada", "value": "CA"}],
            "group_name": "DevOps",
            "purpose": "Cloud hosting",
            "website_url": "https://aws.amazon.com",
            "privacy_policy_url": "https://aws.amazon.com/privacy",
            "security_page_url": "https://aws.amazon.com/security",
            "tos_url": "https://aws.amazon.com/terms",
            "certifications": ["SOC 2", "ISO 27001"],
            "trustcloud_id": "tc-vnd-1",
        },
    ])

    with app.app_context():
        from cli.loaders.vendors import VendorsLoader
        result = VendorsLoader().load(str(data_dir))

        assert result["inserted"] == 1

        v = db.session.get(Vendor, "vnd-001")
        assert v.name == "Amazon Web Services"
        assert v.status == "active"
        assert v.is_subprocessor is True
        assert v.classification == ["customer_confidential"]
        assert v.locations == [{"label": "Canada", "value": "CA"}]
        assert v.group_name == "DevOps"
        assert v.purpose == "Cloud hosting"
        assert v.website_url == "https://aws.amazon.com"
        assert v.certifications == ["SOC 2", "ISO 27001"]


def test_load_vendors_other_data(app, data_dir):
    """Verify owner stored in other_data."""
    write_json(data_dir / "vendors.json", [{
        "id": "vnd-od",
        "name": "Test Vendor",
        "owner": {"id": "owner-1", "name": "Alice"},
    }])

    with app.app_context():
        from cli.loaders.vendors import VendorsLoader
        VendorsLoader().load(str(data_dir))

        v = db.session.get(Vendor, "vnd-od")
        assert v.other_data["owner"]["name"] == "Alice"


def test_load_vendors_system_ids(app, data_dir):
    """Load systems first, then vendors with system_ids M2M."""
    write_json(data_dir / "systems.json", [
        {"id": "sys-m2m-1", "name": "RDS", "type": ["infrastructure"]},
        {"id": "sys-m2m-2", "name": "S3", "type": ["infrastructure"]},
    ])
    write_json(data_dir / "vendors.json", [{
        "id": "vnd-m2m",
        "name": "AWS",
        "system_ids": ["sys-m2m-1", "sys-m2m-2"],
    }])

    with app.app_context():
        from cli.loaders.systems import SystemsLoader
        from cli.loaders.vendors import VendorsLoader
        SystemsLoader().load(str(data_dir))
        VendorsLoader().load(str(data_dir))

        v = db.session.get(Vendor, "vnd-m2m")
        assert len(v.systems) == 2
        system_names = {s.name for s in v.systems}
        assert system_names == {"RDS", "S3"}
        # system_ids also preserved in other_data
        assert v.other_data["system_ids"] == ["sys-m2m-1", "sys-m2m-2"]


def test_load_vendors_missing_system(app, data_dir):
    """Vendor with nonexistent system_id links gracefully (skips that link)."""
    write_json(data_dir / "vendors.json", [{
        "id": "vnd-miss",
        "name": "Vendor Missing Sys",
        "system_ids": ["nonexistent-sys"],
    }])

    with app.app_context():
        from cli.loaders.vendors import VendorsLoader
        result = VendorsLoader().load(str(data_dir))
        assert result["inserted"] == 1

        v = db.session.get(Vendor, "vnd-miss")
        assert len(v.systems) == 0  # no valid systems linked


# --- Stub Loader Tests ---


def test_skip_missing_table(app, data_dir):
    """Risk register loader warns and returns when table absent."""
    write_json(data_dir / "risk-register.json", [
        {"id": "r-1", "name": "Test Risk"},
    ])

    with app.app_context():
        from cli.loaders.risk_register import RiskRegisterLoader
        result = RiskRegisterLoader().load(str(data_dir))
        assert result["inserted"] == 0
        assert result["updated"] == 0


# --- Edge Case Tests ---


def test_empty_json_array(app, data_dir):
    """Empty [] file loads without error."""
    write_json(data_dir / "controls.json", [])

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        result = ControlsLoader().load(str(data_dir))
        assert result["inserted"] == 0
        assert result["skipped"] == 0


def test_missing_file_warns(app, data_dir):
    """Absent file logs warning, continues."""
    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        result = ControlsLoader().load(str(data_dir))
        assert result["inserted"] == 0


def test_unknown_fields_silently_stored(app, data_dir):
    """JSON with extra fields loads fine — stored in other_data."""
    write_json(data_dir / "controls.json", [{
        "id": "ctrl-unk",
        "name": "Unknown Fields",
        "tsc_category": "security",
        "totally_new_field": "should not crash",
        "another_field": 42,
    }])

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        result = ControlsLoader().load(str(data_dir))
        assert result["inserted"] == 1

        c = db.session.get(Control, "ctrl-unk")
        assert c.other_data["totally_new_field"] == "should not crash"
        assert c.other_data["another_field"] == 42


# --- Full Integration Test ---


def test_full_init_run(app, data_dir):
    """End-to-end test: all loaders run successfully."""
    write_json(data_dir / "controls.json", [
        {"id": "ctrl-full", "name": "Full Test Control", "tsc_category": "security"},
    ])
    write_json(data_dir / "tests.json", [{
        "id": "test-full",
        "control_id": "ctrl-full",
        "name": "Full Test",
        "status": "success",
        "evidence_status": "missing",
    }])
    write_json(data_dir / "policy-index.json", [{
        "id": "pol-full",
        "title": "Full Policy",
        "category": "security",
        "status": "approved",
    }])
    write_json(data_dir / "evidence" / "evidence-index.json", [{
        "test_name": "Full Test",
        "evidence_type": "automated",
        "description": "Full evidence",
        "collected_at": "2026-01-01T00:00:00+00:00",
        "collector_name": "full-test",
    }])
    write_json(data_dir / "systems.json", [{"id": "s1", "name": "S1", "type": []}])
    write_json(data_dir / "vendors.json", [{"id": "v1", "name": "V1", "system_ids": ["s1"]}])
    write_json(data_dir / "risk-register.json", [])

    with app.app_context():
        from cli.init import run
        # run() calls sys.exit on missing dir, so we call loaders directly
        from cli.loaders import LOADER_REGISTRY

        totals = {"inserted": 0, "updated": 0, "skipped": 0}
        for loader_class in LOADER_REGISTRY:
            loader = loader_class()
            result = loader.load(str(data_dir))
            totals["inserted"] += result["inserted"]
            totals["updated"] += result["updated"]
            totals["skipped"] += result["skipped"]

        assert Control.query.count() == 1
        assert System.query.count() == 1
        assert TestRecord.query.count() == 1
        assert Policy.query.count() == 1
        assert Vendor.query.count() == 1
        assert Evidence.query.count() == 1
        assert totals["inserted"] == 6  # 1 control + 1 system + 1 test + 1 policy + 1 vendor + 1 evidence
        # Verify vendor M2M
        v = Vendor.query.first()
        assert len(v.systems) == 1
