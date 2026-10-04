"""Tests for the CLI init command and data loaders."""

import json

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db, Control, System, Vendor, TestRecord, Policy, Evidence, RiskRegister, PentestFinding


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

        assert result["created"] == 2
        assert result["skipped"] == 0

        c1 = db.session.get(Control, "ctrl-001")
        assert c1.name == "MFA Enforcement"
        assert c1.category == "security"  # tsc_category mapped to category
        assert c1.trustcloud_id == "tc-001"

        c2 = db.session.get(Control, "ctrl-002")
        assert c2.category == "availability"


def test_load_controls_expanded_fields(app, data_dir):
    """Verify expanded fields are stored in proper columns, not other_data."""
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
        assert c.source_category == "Cloud Infrastructure"
        assert c.control_id_short == "INFRA-8"
        assert c.frequency == "annual"
        assert c.maturity_level == 2
        assert c.group_name == "DevOps"
        assert c.soc2_references[0]["referenceId"] == "CC6.1"
        assert c.owner_id == "owner-1"
        assert c.owner_name == "Alice"
        # owner object still in other_data (nested object preserved)
        assert c.other_data.get("owner", {}).get("name") == "Alice"


def test_idempotent_rerun(app, data_dir):
    """Loading controls twice produces same row count."""
    write_json(data_dir / "controls.json", [
        {"id": "ctrl-idem", "name": "Idempotent", "tsc_category": "security"},
    ])

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        loader = ControlsLoader()
        r1 = loader.load(str(data_dir))
        assert r1["created"] == 1

        r2 = loader.load(str(data_dir))
        assert r2["unchanged"] == 1
        assert r2["updated"] == 0
        assert r2["created"] == 0
        assert Control.query.count() == 1


def test_idempotent_other_data_update(app, data_dir):
    """Changing a field in JSON and re-running updates the column."""
    write_json(data_dir / "controls.json", [
        {"id": "ctrl-upd", "name": "Updatable", "tsc_category": "security", "frequency": "annual"},
    ])

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        loader = ControlsLoader()
        loader.load(str(data_dir))
        assert db.session.get(Control, "ctrl-upd").frequency == "annual"

    write_json(data_dir / "controls.json", [
        {"id": "ctrl-upd", "name": "Updatable", "tsc_category": "security", "frequency": "quarterly"},
    ])

    with app.app_context():
        result = loader.load(str(data_dir))
        assert result["updated"] == 1
        assert result["unchanged"] == 0
        assert db.session.get(Control, "ctrl-upd").frequency == "quarterly"


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


def test_load_tests_expanded_fields(app, data_dir):
    """Verify expanded fields in proper columns."""
    write_json(data_dir / "controls.json", [
        {"id": "ctrl-tod", "name": "Control", "tsc_category": "security"},
    ])
    write_json(data_dir / "tests.json", [{
        "id": "test-tod",
        "control_id": "ctrl-tod",
        "name": "Test Expanded Fields",
        "status": "success",
        "evidence_status": "missing",
        "test_type": "auto_assessment",
        "execution_status": "completed",
        "execution_outcome": "failure",
        "finding": "Something was wrong",
        "comment": "Needs attention",
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
        assert t.test_type == "auto_assessment"
        assert t.execution_status == "completed"
        assert t.execution_outcome == "failure"
        assert t.finding == "Something was wrong"
        assert t.comment == "Needs attention"
        assert t.owner_id == "owner-1"
        assert t.owner_name == "Bob"
        # Denormalized fields still in other_data
        assert t.other_data["control_name"] == "Control"
        # Nested system object in other_data
        assert t.other_data["system"]["name"] == "RDS"


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
        assert result["created"] == 0


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
        assert result["created"] == 1

        p = db.session.get(Policy, "pol-001")
        assert p.title == "Encryption Policy"
        assert p.category == "confidentiality"
        assert p.approved_at is not None
        assert p.approved_at.year == 2026
        assert p.approved_at.month == 3
        assert p.approved_at.day == 25
        assert p.next_review_at.year == 2027


def test_load_policies_expanded_fields(app, data_dir):
    """Verify expanded fields in proper columns."""
    write_json(data_dir / "policy-index.json", [{
        "id": "pol-od",
        "title": "Test Policy",
        "category": "security",
        "short_name": "POL-1",
        "security_group": "Security Operations",
        "soc2_control_ids": ["ctrl-a", "ctrl-b"],
        "group_name": "Engineering",
        "owner": {"id": "own-1", "name": "Admin"},
        "notes": "Some notes",
        "effective_date": "2026-03-25",
    }])

    with app.app_context():
        from cli.loaders.policies import PoliciesLoader
        PoliciesLoader().load(str(data_dir))

        p = db.session.get(Policy, "pol-od")
        assert p.short_name == "POL-1"
        assert p.security_group == "Security Operations"
        assert p.group_name == "Engineering"
        assert p.owner_id == "own-1"
        assert p.owner_name == "Admin"
        assert p.notes == "Some notes"
        assert p.effective_date.year == 2026
        # soc2_control_ids still in other_data (M2M handled separately)
        assert p.other_data["soc2_control_ids"] == ["ctrl-a", "ctrl-b"]


# --- Policy-Control M2M Tests ---


def test_load_policies_control_ids(app, data_dir):
    """Policies with soc2_control_ids get M2M links to controls."""
    write_json(data_dir / "controls.json", [
        {"id": "ctrl-pc1", "name": "MFA", "tsc_category": "security"},
        {"id": "ctrl-pc2", "name": "Encryption", "tsc_category": "confidentiality"},
    ])
    write_json(data_dir / "policy-index.json", [{
        "id": "pol-pc",
        "title": "Auth Policy",
        "category": "security",
        "soc2_control_ids": ["ctrl-pc1", "ctrl-pc2"],
    }])

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        from cli.loaders.policies import PoliciesLoader
        ControlsLoader().load(str(data_dir))
        PoliciesLoader().load(str(data_dir))

        p = db.session.get(Policy, "pol-pc")
        assert len(p.controls) == 2
        control_names = {c.name for c in p.controls}
        assert control_names == {"MFA", "Encryption"}
        # soc2_control_ids preserved in other_data
        assert p.other_data["soc2_control_ids"] == ["ctrl-pc1", "ctrl-pc2"]

        # Verify reverse: control.policies
        c = db.session.get(Control, "ctrl-pc1")
        assert len(c.policies) == 1
        assert c.policies[0].title == "Auth Policy"


def test_load_policies_missing_control_id(app, data_dir):
    """Nonexistent control ID in soc2_control_ids is skipped gracefully."""
    write_json(data_dir / "policy-index.json", [{
        "id": "pol-miss",
        "title": "Missing Control Policy",
        "category": "security",
        "soc2_control_ids": ["nonexistent-ctrl"],
    }])

    with app.app_context():
        from cli.loaders.policies import PoliciesLoader
        result = PoliciesLoader().load(str(data_dir))
        assert result["created"] == 1

        p = db.session.get(Policy, "pol-miss")
        assert len(p.controls) == 0


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
        assert result["created"] == 1

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
        assert result["created"] == 0


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


def test_load_evidence_matching_control_name_fallback(app, data_dir):
    """Evidence resolves via control_name when test_name doesn't match."""
    with app.app_context():
        ctrl = Control(id="ctrl-cn", name="Vuln scanning", category="security")
        db.session.add(ctrl)
        tr = TestRecord(
            id="test-cn",
            control_id="ctrl-cn",
            name="Different name",
            status="passed",
            evidence_status="submitted",
        )
        db.session.add(tr)
        db.session.commit()

    write_json(data_dir / "evidence" / "evidence-index.json", [{
        "test_name": "No match",
        "control_name": "Vuln scanning",
        "evidence_type": "automated",
        "description": "Fallback test",
        "collected_at": "2026-04-01T00:00:00+00:00",
        "collector_name": "test",
    }])

    with app.app_context():
        from cli.loaders.evidence import EvidenceLoader
        result = EvidenceLoader().load(str(data_dir))
        assert result["created"] == 1

        ev = Evidence.query.first()
        assert ev.test_record_id == "test-cn"
        assert ev.other_data["test_name"] == "No match"
        assert ev.other_data["control_name"] == "Vuln scanning"


def test_load_evidence_control_name_not_needed_when_test_matches(app, data_dir):
    """Strategy 1 (test_name) takes priority over control_name."""
    with app.app_context():
        ctrl = Control(id="ctrl-pri", name="Other control", category="security")
        db.session.add(ctrl)
        tr = TestRecord(
            id="test-pri",
            control_id="ctrl-pri",
            name="Exact match",
            status="passed",
            evidence_status="submitted",
        )
        db.session.add(tr)
        db.session.commit()

    write_json(data_dir / "evidence" / "evidence-index.json", [{
        "test_name": "Exact match",
        "control_name": "Something else entirely",
        "evidence_type": "automated",
        "description": "Priority test",
        "collected_at": "2026-04-01T00:00:00+00:00",
        "collector_name": "test",
    }])

    with app.app_context():
        from cli.loaders.evidence import EvidenceLoader
        result = EvidenceLoader().load(str(data_dir))
        assert result["created"] == 1

        ev = Evidence.query.first()
        assert ev.test_record_id == "test-pri"


def test_load_evidence_control_exists_but_no_tests_skips(app, data_dir):
    """Control found but has no tests — evidence is skipped."""
    with app.app_context():
        ctrl = Control(id="ctrl-orphan", name="Orphan control", category="security")
        db.session.add(ctrl)
        db.session.commit()

    write_json(data_dir / "evidence" / "evidence-index.json", [{
        "test_name": "Orphan control",
        "evidence_type": "automated",
        "description": "Should be skipped",
        "collected_at": "2026-04-01T00:00:00+00:00",
        "collector_name": "test",
    }])

    with app.app_context():
        from cli.loaders.evidence import EvidenceLoader
        result = EvidenceLoader().load(str(data_dir))
        assert result["skipped"] == 1
        assert result["created"] == 0


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

        assert result["created"] == 2

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

        assert result["created"] == 1

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
        assert result["created"] == 1

        v = db.session.get(Vendor, "vnd-miss")
        assert len(v.systems) == 0  # no valid systems linked


# --- Stub Loader Tests ---


def test_skip_loader_without_model(app, data_dir):
    """A loader with model_class=None imports nothing and says so."""
    from cli.loaders.base import BaseLoader

    class FakeLoader(BaseLoader):
        model_class = None
        file_name = "fake.json"

    write_json(data_dir / "fake.json", [{"id": "f-1", "name": "Fake"}])

    with app.app_context():
        result = FakeLoader().load(str(data_dir))
        assert result["created"] == 0
        assert result["updated"] == 0
        assert "no model" in result["errors"][0]


# --- Pentest Findings Loader Tests ---


def test_load_pentest_findings(app, data_dir):
    """Load pentest findings from layered directory structure."""
    layer1_dir = data_dir / "pentest-evidence" / "layer1"
    layer1_dir.mkdir(parents=True)

    write_json(layer1_dir / "scan-001-repo.json", {
        "repo": "TestRepo",
        "scan_id": "scan-001",
        "timestamp": "2026-03-28T143840Z",
        "finding_count": 2,
        "findings": [
            {
                "severity": "HIGH",
                "dependency": {"name": "pkg", "version": "1.0", "source_file": "package.json"},
                "vulnerability": {"id": "CVE-2026-001", "summary": "Bad vuln"},
                "remediation": "Upgrade pkg to 2.0",
                "soc2_controls": ["CC7.1", "CC7.2"],
            },
            {
                "severity": "LOW",
                "dependency": {"name": "other", "version": "3.0", "source_file": "go.mod"},
                "vulnerability": {"id": "CVE-2026-002", "summary": "Minor issue"},
                "remediation": "Upgrade other to 4.0",
                "soc2_controls": ["CC7.1"],
            },
        ],
    })

    with app.app_context():
        from cli.loaders.pentest_findings import PentestFindingsLoader
        result = PentestFindingsLoader().load(str(data_dir))

        assert result["created"] == 2
        findings = PentestFinding.query.all()
        assert len(findings) == 2

        high = PentestFinding.query.filter_by(severity="HIGH").first()
        assert high.layer == 1
        assert high.repo == "TestRepo"
        assert high.scan_id == "scan-001"
        assert high.summary == "Bad vuln"
        assert high.remediation == "Upgrade pkg to 2.0"
        assert high.soc2_controls == ["CC7.1", "CC7.2"]
        assert high.source_file == "layer1/scan-001-repo.json"
        # Full finding preserved in other_data
        assert high.other_data["severity"] == "HIGH"
        assert high.other_data["vulnerability"]["id"] == "CVE-2026-001"


def test_load_pentest_findings_idempotent(app, data_dir):
    """Running pentest loader twice produces same count."""
    layer2_dir = data_dir / "pentest-evidence" / "layer2"
    layer2_dir.mkdir(parents=True)

    write_json(layer2_dir / "scan-idem.json", {
        "scan_id": "scan-idem",
        "findings": [{"severity": "MEDIUM", "remediation": "Fix it", "soc2_controls": []}],
    })

    with app.app_context():
        from cli.loaders.pentest_findings import PentestFindingsLoader
        loader = PentestFindingsLoader()
        r1 = loader.load(str(data_dir))
        assert r1["created"] == 1

        r2 = loader.load(str(data_dir))
        assert r2["unchanged"] == 1
        assert r2["updated"] == 0
        assert r2["created"] == 0
        assert PentestFinding.query.count() == 1


def test_load_pentest_findings_layer4_structured_fields(app, data_dir):
    """Layer 4 findings carry structured remediation and summary; the loader
    stores them as text, keeps the structure in other_data, and stays
    deterministic across reruns."""
    layer4_dir = data_dir / "pentest-evidence" / "layer4"
    layer4_dir.mkdir(parents=True)

    structured_remediation = {"file_path": "App/app/routes/user.py", "function_name": "unknown"}
    write_json(layer4_dir / "scan-l4--agent.json", {
        "scan_id": "scan-l4",
        "repo_name": "",
        "timestamp": "2026-06-15T130416Z",
        "findings": [
            {
                "severity": "HIGH",
                "file_path": "App/app/__init__.py",
                "summary": "CORS misconfiguration enables data exfiltration",
                "remediation": structured_remediation,
                "soc2_controls": ["CC7.1"],
            },
            {
                "severity": "MEDIUM",
                "summary": {"title": "Structured summary", "detail": "x"},
                "remediation": None,
                "dependency": "not-a-dict",
                "finding": "not-a-dict",
                "vulnerability": "not-a-dict",
            },
            "a bare string finding",
        ],
    })

    with app.app_context():
        from cli.loaders.pentest_findings import PentestFindingsLoader
        loader = PentestFindingsLoader()
        result = loader.load(str(data_dir))
        assert result["created"] == 3

        high = PentestFinding.query.filter_by(severity="HIGH").first()
        assert high.layer == 4
        assert high.remediation == json.dumps(structured_remediation, sort_keys=True)
        assert high.other_data["remediation"] == structured_remediation
        assert high.file_path == "App/app/__init__.py"

        medium = PentestFinding.query.filter_by(severity="MEDIUM").first()
        assert medium.summary == str({"title": "Structured summary", "detail": "x"})
        assert medium.remediation is None
        assert medium.file_path is None

        bare = PentestFinding.query.filter(PentestFinding.severity.is_(None)).first()
        assert bare.summary == "a bare string finding"

        rerun = loader.load(str(data_dir))
        assert rerun["created"] == 0
        assert rerun["unchanged"] == 3
        assert rerun["updated"] == 0
        assert PentestFinding.query.count() == 3


# --- Risk Register Loader Tests ---


def test_load_risk_register(app, data_dir):
    """Load risk register entries."""
    write_json(data_dir / "risk-register.json", [{
        "id": "risk-001",
        "name": "Data Breach Risk",
        "description": "Risk of unauthorized data access",
        "likelihood": 3,
        "impact": 5,
        "risk_score": 15.0,
        "treatment": "mitigate",
        "treatment_plan": "Implement MFA and encryption",
        "status": "open",
        "owner": {"id": "own-1", "name": "Alice"},
        "group_name": "Security",
    }])

    with app.app_context():
        from cli.loaders.risk_register import RiskRegisterLoader
        result = RiskRegisterLoader().load(str(data_dir))
        assert result["created"] == 1

        r = db.session.get(RiskRegister, "risk-001")
        assert r.name == "Data Breach Risk"
        assert r.likelihood == 3
        assert r.impact == 5
        assert r.risk_score == 15.0
        assert r.treatment == "mitigate"
        assert r.status == "open"
        assert r.owner_id == "own-1"
        assert r.owner_name == "Alice"
        assert r.group_name == "Security"


# --- Edge Case Tests ---


def test_empty_json_array(app, data_dir):
    """Empty [] file loads without error."""
    write_json(data_dir / "controls.json", [])

    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        result = ControlsLoader().load(str(data_dir))
        assert result["created"] == 0
        assert result["skipped"] == 0


def test_missing_file_warns(app, data_dir):
    """Absent file logs warning, continues."""
    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        result = ControlsLoader().load(str(data_dir))
        assert result["created"] == 0


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
        assert result["created"] == 1

        c = db.session.get(Control, "ctrl-unk")
        assert c.other_data["totally_new_field"] == "should not crash"
        assert c.other_data["another_field"] == 42


# --- Full Integration Test ---


def test_full_init_run(app, data_dir, monkeypatch):
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
        "soc2_control_ids": ["ctrl-full"],
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
    write_json(data_dir / "risk-register.json", [{"id": "r1", "name": "Risk 1"}])

    # decision logs are not part of init
    (data_dir / "decision-logs").mkdir()
    (data_dir / "decision-logs" / "2026-01-01T000000Z_s-init.jsonl").write_text("{}\n")

    monkeypatch.setattr("app.create_app", lambda: app)
    from cli.init import run

    result = run(str(data_dir))
    totals = result["totals"]
    assert totals["created"] == 7  # 1 control + 1 system + 1 test + 1 policy + 1 vendor + 1 evidence + 1 risk
    assert totals["updated"] == 0
    assert result["decision_logs"]["created"] == 0

    with app.app_context():
        assert Control.query.count() == 1
        assert System.query.count() == 1
        assert TestRecord.query.count() == 1
        assert Policy.query.count() == 1
        assert Vendor.query.count() == 1
        assert Evidence.query.count() == 1
        assert RiskRegister.query.count() == 1
        # Verify vendor M2M
        v = Vendor.query.first()
        assert len(v.systems) == 1
        # Verify policy-control M2M
        p = Policy.query.first()
        assert len(p.controls) == 1

    rerun = run(str(data_dir))["totals"]
    assert rerun["created"] == 0
    assert rerun["updated"] == 0
    assert rerun["unchanged"] == 7


def test_init_run_missing_dir_exits(tmp_path):
    from cli.init import run

    with pytest.raises(SystemExit):
        run(str(tmp_path / "missing"))


def test_init_run_dry_run_reports_errors(app, data_dir, monkeypatch, caplog):
    write_json(data_dir / "tests.json", [
        {"id": f"t-{n}", "control_id": "ghost", "name": "Orphan"} for n in range(105)
    ])
    monkeypatch.setattr("app.create_app", lambda: app)
    from cli.init import run

    with caplog.at_level("INFO", logger="cli.init"):
        result = run(str(data_dir), dry_run=True)
    assert result["totals"]["skipped"] == 105
    assert result["errors_omitted"] == 5
    assert "DRY RUN" in caplog.text
    assert "... and 5 more" in caplog.text
    assert TestRecord.query.count() == 0


def test_init_module_main(app, data_dir, monkeypatch):
    import runpy
    import sys

    write_json(data_dir / "controls.json", [{"id": "c-main", "name": "Main", "tsc_category": "security"}])
    monkeypatch.setattr("app.create_app", lambda: app)
    monkeypatch.setattr(sys, "argv", ["cli.init", "--data-dir", str(data_dir)])
    monkeypatch.delitem(sys.modules, "cli.init", raising=False)
    runpy.run_module("cli.init", run_name="__main__")
    assert db.session.get(Control, "c-main") is not None


# --- Record-building details ---


def test_value_map_ignores_unhashable_values(app, data_dir):
    write_json(data_dir / "controls.json", [{"id": "ctrl-h", "name": "C", "tsc_category": "security"}])
    write_json(data_dir / "tests.json", [{
        "id": "test-h", "control_id": "ctrl-h", "name": "Unhashable", "status": ["success"],
    }])
    with app.app_context():
        from cli.loaders.controls import ControlsLoader
        from cli.loaders.tests import TestsLoader
        ControlsLoader().load(str(data_dir))
        result = TestsLoader().load(str(data_dir))
        assert result["created"] == 1
        assert db.session.get(TestRecord, "test-h").status == '["success"]'


def test_parse_date_variants(app):
    from datetime import datetime, timezone
    from cli.loaders.base import BaseLoader

    loader = BaseLoader()
    moment = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert loader._parse_date(moment) is moment
    assert loader._parse_date("   ") is None
    assert loader._parse_date("2026-3-5") == datetime(2026, 3, 5, tzinfo=timezone.utc)
    assert loader._parse_date("next tuesday") is None
    assert loader._parse_date("2026-04-16T193413Z") == datetime(2026, 4, 16, 19, 34, 13, tzinfo=timezone.utc)


def test_parsed_data_may_carry_datetimes(app):
    from datetime import datetime
    from app.services.evidence_import import import_dataset_file

    items = [{"id": "r-dt", "name": "Risk", "review_date": datetime(2026, 5, 1, 9, 0)}]
    assert import_dataset_file("risk-register", "risk-register.json", items).created == 1
    assert import_dataset_file("risk-register", "risk-register.json", items).unchanged == 1


def test_field_map_clash_goes_to_other_data(app, data_dir):
    write_json(data_dir / "systems.json", [{
        "id": "sys-clash", "name": "Clash", "type": ["application"], "system_type": "ignored",
    }])
    with app.app_context():
        from cli.loaders.systems import SystemsLoader
        SystemsLoader().load(str(data_dir))
        s = db.session.get(System, "sys-clash")
        assert s.system_type == ["application"]
        assert s.other_data["system_type"] == "ignored"


def test_load_evidence_test_name_matches_control_with_tests(app, data_dir):
    """Strategy 2: test_name equals a control name; its first test is used."""
    with app.app_context():
        db.session.add(Control(id="ctrl-s2", name="Named like a control", category="security"))
        db.session.add(TestRecord(id="test-s2", control_id="ctrl-s2", name="Something else",
                                  status="passed", evidence_status="submitted"))
        db.session.commit()

    write_json(data_dir / "evidence" / "evidence-index.json", [{
        "test_name": "Named like a control", "evidence_type": "automated",
        "collected_at": "2026-04-01T00:00:00+00:00",
    }])
    with app.app_context():
        from cli.loaders.evidence import EvidenceLoader
        assert EvidenceLoader().load(str(data_dir))["created"] == 1
        assert Evidence.query.one().test_record_id == "test-s2"


# --- `python -m cli import` ---


def _parse_import_args(argv):
    import argparse
    from cli import import_cmd

    parser = argparse.ArgumentParser(prog="cli")
    subparsers = parser.add_subparsers(dest="command")
    import_cmd.add_parser(subparsers)
    return parser.parse_args(argv)


def test_import_cmd_parser():
    args = _parse_import_args(["import", "--data-dir", "/d", "--dry-run", "--no-decision-logs",
                               "--dataset", "controls", "--dataset", "tests", "--json"])
    assert (args.data_dir, args.dry_run, args.no_decision_logs, args.json) == ("/d", True, True, True)
    assert args.datasets == ["controls", "tests"]
    from cli import import_cmd
    assert args.func is import_cmd.run
    with pytest.raises(SystemExit):
        _parse_import_args(["import", "--data-dir", "/d", "--dataset", "bogus"])


def test_import_cmd_json_output(app, data_dir, monkeypatch, capsys):
    from cli import import_cmd

    write_json(data_dir / "controls.json", [{"id": "c-j", "name": "J", "tsc_category": "security"}])
    (data_dir / "decision-logs").mkdir()
    (data_dir / "decision-logs" / "2026-01-01T000000Z_s-json.jsonl").write_text(
        json.dumps({"type": "user", "message": {"content": "hi"}}) + "\n")
    monkeypatch.setattr("app.create_app", lambda: app)

    status = import_cmd.run(_parse_import_args(["import", "--data-dir", str(data_dir), "--json"]))
    captured = capsys.readouterr()
    assert status == 0
    summary = json.loads(captured.out)
    assert summary["datasets"]["controls"]["created"] == 1
    assert summary["decision_logs"]["created"] == 1
    assert summary["dry_run"] is False
    assert "controls: created=1" in captured.err


def test_import_cmd_text_output_and_failures(app, data_dir, monkeypatch, capsys):
    from cli import import_cmd

    write_json(data_dir / "controls.json", [{"id": "c-t", "name": "T", "tsc_category": "security"}])
    (data_dir / "tests.json").write_text("{broken")
    monkeypatch.setattr("app.create_app", lambda: app)

    status = import_cmd.main(["--data-dir", str(data_dir), "--dry-run", "--no-decision-logs",
                              "--dataset", "controls", "--dataset", "tests"])
    out = capsys.readouterr().out
    assert status == 1
    assert out.startswith("DRY RUN")
    assert "controls: created=1" in out
    assert "tests.json: not imported" in out
    assert Control.query.count() == 0

    assert import_cmd.run(_parse_import_args(["import", "--data-dir", str(data_dir / "nope")])) == 1
    assert "does not exist" in capsys.readouterr().err


def test_import_cmd_format_summary_lists_omitted_errors():
    from cli.import_cmd import format_summary

    counts = {"created": 1, "updated": 2, "unchanged": 3, "deleted": 4, "skipped": 5}
    text = format_summary({
        "datasets": {"controls": counts}, "totals": counts,
        "decision_logs": {"created": 0, "replaced": 1, "unchanged": 0, "kept_existing": 0, "failed": 0},
        "errors": ["one"], "errors_omitted": 3,
    })
    assert text.startswith("Import complete")
    assert "decision-logs: created=0 replaced=1" in text
    assert "... and 3 more" in text
