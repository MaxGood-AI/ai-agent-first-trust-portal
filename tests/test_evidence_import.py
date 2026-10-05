"""Tests for the diff-only evidence import engine (app.services.evidence_import)."""

import collections
import contextlib
import gzip
import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import event
from sqlalchemy.exc import OperationalError

from app import create_app
from app.config import TestConfig
from app.models import (
    Control, DecisionLogEntry, DecisionLogSession, DecisionLogTranscript, Evidence, PentestFinding,
    Policy, RiskRegister, System, TestRecord, Vendor, db,
)
from app.services import chunked_files, evidence_import, team_service
from app.services.evidence_import import (
    AUTHORED_EVIDENCE_MAPPINGS, DATASET_ORDER, DEFAULT_DATASETS, DEFAULT_EVIDENCE_MAPPINGS, ImportCounts,
    classify_path, import_dataset_file,
    import_decision_log, import_directory, is_deadlock, remove_dataset_file,
)
from app.services.transcript_ingest import parse_transcript
from cli.loaders.pentest_findings import PentestFindingsLoader, finding_id


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@contextlib.contextmanager
def count_writes():
    """Count INSERT / UPDATE / DELETE statements sent to the database."""
    counts = collections.Counter()
    statements = []

    def before(conn, cursor, statement, parameters, context, executemany):
        verb = statement.lstrip().split(None, 1)[0].upper()
        if verb in ("INSERT", "UPDATE", "DELETE"):
            counts[verb] += 1
            statements.append(statement)

    event.listen(db.engine, "before_cursor_execute", before)
    try:
        yield counts, statements
    finally:
        event.remove(db.engine, "before_cursor_execute", before)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


CONTROLS = [
    {"id": "c1", "name": "MFA", "tsc_category": "security", "category": "Identity",
     "frequency": "annual", "maturity_level": 2, "soc2_references": [{"referenceId": "CC6.1", "d": "x"}],
     "owner": {"id": "o1", "name": "Alice"}},
    {"id": "c2", "name": "Backups", "tsc_category": "availability"},
]
SYSTEMS = [
    {"id": "s1", "name": "RDS", "type": ["infrastructure"], "risk_score": 55.56},
    {"id": "s2", "name": "S3", "type": ["infrastructure"], "risk_score": 10},
]
TESTS = [
    {"id": "t1", "control_id": "c1", "name": "MFA test", "status": "success",
     "evidence_status": "up_to_date", "due_at": "2026-04-15", "system": {"id": "s1", "name": "RDS"}},
    {"id": "t2", "control_id": "c2", "name": "Backup test", "status": "not_run",
     "evidence_status": "missing", "last_executed_at": "2026-03-01T10:00:00-04:00"},
]
POLICIES = [
    {"id": "p1", "title": "Access", "category": "security", "version": "1.0",
     "approved_at": "2026-03-25", "soc2_control_ids": ["c1", "c2"]},
]
VENDORS = [
    {"id": "v1", "name": "Cloud", "is_subprocessor": True, "system_ids": ["s1", "s2"],
     "locations": [{"label": "Canada", "value": "CA"}]},
    {"id": "v2", "name": "Mail", "system_ids": []},
]
EVIDENCE = [
    {"test_name": "MFA test", "evidence_type": "automated", "file_path": "a.json",
     "collected_at": "2026-03-26T10:59:16+00:00", "collector_name": "scanner"},
    {"test_name": "Backup test", "evidence_type": "link", "url": "https://example.com/x",
     "collected_at": "2026-03-27T00:00:00+00:00", "collector_name": "manual"},
]
RISKS = [{"id": "r1", "name": "Breach", "likelihood": 3, "impact": 5, "risk_score": 15,
          "review_date": "2026-06-01", "owner": {"id": "o1", "name": "Alice"}}]
SCAN_L1 = {
    "repo": "RepoA", "scan_id": "scan-1", "timestamp": "2026-04-16T193413Z",
    "findings": [
        {"severity": "HIGH", "dependency": {"name": "pkg", "source_file": "package.json"},
         "vulnerability": {"id": "CVE-1", "summary": "Bad"}, "remediation": "Upgrade",
         "soc2_controls": ["CC7.1"]},
        {"severity": "HIGH", "dependency": {"name": "pkg", "source_file": "package.json"},
         "vulnerability": {"id": "CVE-1", "summary": "Bad"}, "remediation": "Upgrade",
         "soc2_controls": ["CC7.1"]},
        {"severity": "LOW", "message": "minor"},
    ],
}
SCAN_L4 = {
    "repo_name": "", "scan_id": "scan-4", "timestamp": "2026-06-15T130416Z",
    "findings": [{"severity": "MEDIUM", "summary": {"title": "t"}, "remediation": {"file": "x"}},
                 "a bare string finding"],
}
SUMMARY = {"total_dependencies_scanned": 3, "repos_clean": []}


@pytest.fixture
def repo(tmp_path):
    write_json(tmp_path / "controls.json", CONTROLS)
    write_json(tmp_path / "systems.json", SYSTEMS)
    write_json(tmp_path / "tests.json", TESTS)
    write_json(tmp_path / "policy-index.json", POLICIES)
    write_json(tmp_path / "vendors.json", VENDORS)
    write_json(tmp_path / "evidence" / "evidence-index.json", EVIDENCE)
    write_json(tmp_path / "risk-register.json", RISKS)
    write_json(tmp_path / "pentest-evidence" / "layer1" / "scan-1-RepoA.json", SCAN_L1)
    write_json(tmp_path / "pentest-evidence" / "layer1" / "scan-1-summary.json", SUMMARY)
    write_json(tmp_path / "pentest-evidence" / "layer4" / "scan-4--agent.json", SCAN_L4)
    (tmp_path / "pentest-evidence" / "notes").mkdir()
    (tmp_path / "pentest-evidence" / "layer4" / "README.md").write_text("ignored")
    return tmp_path


RECORD_COUNT = 2 + 2 + 2 + 1 + 2 + 2 + 1 + 5  # controls..risks + 5 findings


# --------------------------------------------------------------------------
# Idempotency: the core requirement
# --------------------------------------------------------------------------

def test_second_import_of_identical_data_writes_nothing(app, repo):
    first = import_directory(str(repo), datasets=DATASET_ORDER)
    assert first["totals"]["created"] == RECORD_COUNT
    assert first["errors"] == []
    assert first["failed_files"] == 0
    assert PentestFinding.query.count() == 5
    assert len(db.session.get(Policy, "p1").controls) == 2
    assert len(db.session.get(Vendor, "v1").systems) == 2

    with count_writes() as (writes, _):
        second = import_directory(str(repo), datasets=DATASET_ORDER)

    assert second["totals"] == {"created": 0, "updated": 0, "unchanged": RECORD_COUNT,
                                "deleted": 0, "skipped": 1, "retired": 0}  # the pentest summary file
    assert sum(writes.values()) == 0
    for name in DATASET_ORDER:
        assert second["datasets"][name]["created"] == 0
        assert second["datasets"][name]["updated"] == 0


def test_single_changed_field_updates_exactly_one_row(app, repo):
    import_directory(str(repo), datasets=DATASET_ORDER)
    changed = [dict(CONTROLS[0], frequency="quarterly"), CONTROLS[1]]

    with count_writes() as (writes, statements):
        counts = import_dataset_file("controls", "controls.json", json.dumps(changed))
        db.session.commit()

    assert (counts.created, counts.updated, counts.unchanged) == (0, 1, 1)
    assert writes["UPDATE"] == 1 and writes["INSERT"] == 0 and writes["DELETE"] == 0
    assert "frequency" in statements[0] and "name" not in statements[0].split("WHERE")[0]
    assert db.session.get(Control, "c1").frequency == "quarterly"


def test_import_dataset_file_accepts_bytes_text_and_parsed(app):
    assert import_dataset_file("controls", "controls.json", json.dumps(CONTROLS).encode()).created == 2
    assert import_dataset_file("controls", "controls.json", json.dumps(CONTROLS)).unchanged == 2
    assert import_dataset_file("controls", "controls.json", CONTROLS).unchanged == 2
    bom = b"\xef\xbb\xbf" + json.dumps(CONTROLS).encode()
    assert import_dataset_file("controls", "controls.json", bom).unchanged == 2


@pytest.mark.parametrize("data", [b"{not json", "[1,", b"\xff\xfe\x00", 42])
def test_import_dataset_file_rejects_unparseable_input(app, data):
    with pytest.raises(ValueError):
        import_dataset_file("controls", "controls.json", data)


def test_import_dataset_file_rejects_unknown_dataset(app):
    with pytest.raises(ValueError, match="unknown dataset"):
        import_dataset_file("nope", "nope.json", [])


def test_import_dataset_file_flushes_but_does_not_commit(app):
    import_dataset_file("controls", "controls.json", CONTROLS)
    assert Control.query.count() == 2
    db.session.rollback()
    assert Control.query.count() == 0


# --------------------------------------------------------------------------
# Value normalisation
# --------------------------------------------------------------------------

def test_naive_stored_datetime_equals_aware_file_value(app):
    db.session.add(Policy(id="p-dt", title="T", category="security",
                          approved_at=datetime(2026, 3, 25, 14, 0, 0)))
    db.session.commit()

    for value in ("2026-03-25T14:00:00+00:00", "2026-03-25T10:00:00-04:00", "2026-03-25T14:00:00Z"):
        item = {"id": "p-dt", "title": "T", "category": "security", "approved_at": value}
        with count_writes() as (writes, _):
            counts = import_dataset_file("policies", "policy-index.json", [item])
        assert counts.unchanged == 1, value
        assert sum(writes.values()) == 0


def test_aware_datetimes_are_stored_as_naive_utc(app):
    import_dataset_file("controls", "controls.json", CONTROLS)
    import_dataset_file("systems", "systems.json", SYSTEMS)
    import_dataset_file("tests", "tests.json", TESTS)
    db.session.commit()
    stored = db.session.get(TestRecord, "t2").last_executed_at
    assert stored.tzinfo is None
    assert stored == datetime(2026, 3, 1, 14, 0, 0)


def test_json_columns_compare_canonically(app):
    import_dataset_file("controls", "controls.json", CONTROLS)
    db.session.commit()
    reordered = dict(CONTROLS[0], soc2_references=[{"d": "x", "referenceId": "CC6.1"}])
    assert import_dataset_file("controls", "controls.json", [reordered]).unchanged == 1
    changed = dict(CONTROLS[0], soc2_references=[{"d": "y", "referenceId": "CC6.1"}])
    assert import_dataset_file("controls", "controls.json", [changed]).updated == 1


def test_scalar_values_compare_as_their_column_type(app):
    items = [{"id": "p-v", "title": "T", "category": "security", "version": 1.0,
              "approved_by": True, "short_name": 7}]
    import_dataset_file("policies", "policy-index.json", items)
    db.session.commit()
    policy = db.session.get(Policy, "p-v")
    assert (policy.version, policy.approved_by, policy.short_name) == ("1.0", "true", "7")
    assert import_dataset_file("policies", "policy-index.json", items).unchanged == 1

    risks = [{"id": "r-c", "name": "R", "likelihood": "3", "impact": 4.0, "risk_score": "12.5"}]
    import_dataset_file("risk-register", "risk-register.json", risks)
    db.session.commit()
    risk = db.session.get(RiskRegister, "r-c")
    assert (risk.likelihood, risk.impact, risk.risk_score) == (3, 4, 12.5)
    assert import_dataset_file("risk-register", "risk-register.json", risks).unchanged == 1


@pytest.mark.parametrize("column_name,value,expected", [
    ("name", {"a": 1}, '{"a": 1}'),
    ("name", object, object),
    ("is_subprocessor", 1, True),
    ("is_subprocessor", "yes", "yes"),
    ("likelihood", True, 1),
    ("likelihood", 2.5, 2.5),
    ("likelihood", "three", "three"),
    ("risk_score", True, 1.0),
    ("risk_score", "high", "high"),
    ("risk_score", 2.5, 2.5),
    ("review_date", "not-a-date", "not-a-date"),
])
def test_coerce_value_edge_cases(app, column_name, value, expected):
    model = Vendor if column_name == "is_subprocessor" else RiskRegister
    column = model.__table__.columns[column_name]
    assert evidence_import.coerce_value(column, value) == expected


def test_coerce_value_keeps_aware_datetimes_for_timezone_columns(app):
    column = DecisionLogSession.__table__.columns["replaced_at"]
    naive = datetime(2026, 1, 1, 12, 0)
    assert evidence_import.coerce_value(column, naive) == naive.replace(tzinfo=timezone.utc)


def test_values_equal_handles_none(app):
    column = Control.__table__.columns["frequency"]
    assert evidence_import.values_equal(column, None, None)
    assert not evidence_import.values_equal(column, None, "annual")
    assert not evidence_import.values_equal(column, "annual", None)


def test_updated_at_is_bookkeeping(app):
    item = {"id": "c-u", "name": "U", "tsc_category": "security", "updated_at": "2026-01-01T00:00:00Z"}
    import_dataset_file("controls", "controls.json", [item])
    db.session.commit()
    assert db.session.get(Control, "c-u").updated_at == datetime(2026, 1, 1)

    later = dict(item, updated_at="2026-02-01T00:00:00Z")
    with count_writes() as (writes, _):
        assert import_dataset_file("controls", "controls.json", [later]).unchanged == 1
    assert sum(writes.values()) == 0

    real_change = dict(later, name="Renamed")
    assert import_dataset_file("controls", "controls.json", [real_change]).updated == 1
    db.session.commit()
    assert db.session.get(Control, "c-u").updated_at == datetime(2026, 2, 1)


def test_columns_absent_from_file_keep_their_value(app):
    import_dataset_file("controls", "controls.json", CONTROLS)
    db.session.commit()
    trimmed = {"id": "c1", "name": "MFA", "tsc_category": "security"}
    counts = import_dataset_file("controls", "controls.json", [trimmed])
    db.session.commit()
    control = db.session.get(Control, "c1")
    assert counts.updated == 1  # other_data lost the owner object
    assert control.frequency == "annual"
    assert control.owner_name == "Alice"
    assert control.other_data == {}


# --------------------------------------------------------------------------
# Validation and references
# --------------------------------------------------------------------------

def test_invalid_items_are_skipped_with_errors(app):
    items = [
        "not an object",
        {"name": "no id", "tsc_category": "security"},
        {"id": "c-missing", "name": "No category"},
        {"id": "c-long", "name": "x" * 300, "tsc_category": "security"},
        {"id": "c-dup", "name": "First", "tsc_category": "security"},
        {"id": "c-dup", "name": "Second", "tsc_category": "security"},
    ]
    counts = import_dataset_file("controls", "controls.json", items)
    assert (counts.created, counts.skipped) == (1, 5)
    assert db.session.get(Control, "c-dup").name == "Second"
    joined = "\n".join(counts.errors)
    for fragment in ("expected a JSON object", "id is missing", "missing required field(s): category",
                     "longer than 255", "duplicate id"):
        assert fragment in joined

    nulled = import_dataset_file("controls", "controls.json",
                                 [{"id": "c-dup", "name": None, "tsc_category": "security"}])
    assert nulled.skipped == 1
    assert "set to null: name" in nulled.errors[0]


def test_non_array_dataset_file_is_skipped(app):
    counts = import_dataset_file("controls", "controls.json", {"id": "c1"})
    assert counts.skipped == 1
    assert "expected a JSON array" in counts.errors[0]


def test_tests_require_their_control_and_drop_unknown_systems(app):
    import_dataset_file("controls", "controls.json", CONTROLS)
    db.session.commit()
    items = [
        {"id": "t-ok", "control_id": "c1", "name": "OK", "system": {"id": "ghost"}},
        {"id": "t-bad", "control_id": "nope", "name": "Bad"},
        {"id": "t-none", "name": "No control"},
    ]
    counts = import_dataset_file("tests", "tests.json", items)
    assert (counts.created, counts.skipped) == (1, 2)
    assert db.session.get(TestRecord, "t-ok").system_id is None
    joined = "\n".join(counts.errors)
    assert "system_id 'ghost' not found" in joined
    assert "control_id 'nope' not found" in joined
    assert "control_id is missing" in joined


def test_evidence_resolution_and_errors(app):
    import_dataset_file("controls", "controls.json", CONTROLS)
    import_dataset_file("tests", "tests.json", TESTS[1:])
    db.session.commit()
    items = [
        dict(EVIDENCE[1]),
        {"test_name": "Unknown", "control_name": "Also unknown", "evidence_type": "link",
         "collected_at": "2026-01-01"},
        {"test_name": ["not", "a", "string"], "evidence_type": "link"},
    ]
    counts = import_dataset_file("evidence", "evidence/evidence-index.json", items)
    assert (counts.created, counts.skipped) == (1, 2)
    assert "no test matches test_name='Unknown' or control_name='Also unknown'" in counts.errors[0]
    assert "must be strings" in counts.errors[1]
    evidence = Evidence.query.one()
    assert evidence.test_record_id == "t2"
    assert evidence.other_data["test_name"] == "Backup test"


def test_policy_links_sync_only_when_the_set_differs(app):
    import_dataset_file("controls", "controls.json", CONTROLS)
    import_dataset_file("policies", "policy-index.json", POLICIES)
    db.session.commit()

    same_set = [dict(POLICIES[0], soc2_control_ids=["c2", "c1", "c1"])]
    with count_writes() as (writes, _):
        counts = import_dataset_file("policies", "policy-index.json", same_set)
    # the column other_data changed (list order), the links did not
    assert counts.updated == 1
    assert writes["DELETE"] == 0 and writes["INSERT"] == 0
    db.session.commit()

    fewer = [dict(POLICIES[0], soc2_control_ids=["c2", "ghost", 5])]
    counts = import_dataset_file("policies", "policy-index.json", fewer)
    db.session.commit()
    assert counts.updated == 1
    assert [c.id for c in db.session.get(Policy, "p1").controls] == ["c2"]
    assert any("'ghost' not found" in e for e in counts.errors)
    assert any("5 not found" in e for e in counts.errors)

    with count_writes() as (writes, _):
        again = import_dataset_file("policies", "policy-index.json", fewer)
    assert again.unchanged == 1
    assert sum(writes.values()) == 0

    empty = import_dataset_file("policies", "policy-index.json", [dict(POLICIES[0], soc2_control_ids=[])])
    db.session.commit()
    assert empty.updated == 1
    assert [c.id for c in db.session.get(Policy, "p1").controls] == ["c2"]  # untouched

    not_a_list = import_dataset_file("policies", "policy-index.json",
                                     [dict(POLICIES[0], soc2_control_ids="c1")])
    assert any("is not a list" in e for e in not_a_list.errors)


def test_link_change_alone_counts_as_update(app):
    import_dataset_file("systems", "systems.json", SYSTEMS)
    import_dataset_file("vendors", "vendors.json", VENDORS)
    db.session.commit()
    vendor = db.session.get(Vendor, "v1")
    vendor.systems = [db.session.get(System, "s1")]  # edited in the portal
    db.session.commit()

    counts = import_dataset_file("vendors", "vendors.json", VENDORS)
    db.session.commit()
    assert (counts.updated, counts.unchanged) == (1, 1)
    assert {s.id for s in db.session.get(Vendor, "v1").systems} == {"s1", "s2"}


# --------------------------------------------------------------------------
# Dry run
# --------------------------------------------------------------------------

def test_dry_run_writes_nothing(app, repo):
    with count_writes() as (writes, _):
        result = import_directory(str(repo), dry_run=True, datasets=DATASET_ORDER)
    assert sum(writes.values()) == 0
    assert Control.query.count() == 0
    # ids the run would create satisfy later reference checks...
    assert result["datasets"]["tests"]["created"] == 2
    assert result["datasets"]["policies"]["errors"] == []
    # ...but evidence resolves tests by name against stored rows only
    assert result["datasets"]["evidence"]["skipped"] == 2

    import_directory(str(repo), datasets=DATASET_ORDER)
    changed = [dict(CONTROLS[0], name="Changed"), CONTROLS[1]]
    with count_writes() as (writes, _):
        counts = import_dataset_file("controls", "controls.json", changed, dry_run=True)
    assert (counts.updated, counts.unchanged) == (1, 1)
    assert sum(writes.values()) == 0
    assert db.session.get(Control, "c1").name == "MFA"


# --------------------------------------------------------------------------
# Pentest findings
# --------------------------------------------------------------------------

L1_PATH = "pentest-evidence/layer1/scan-1-RepoA.json"


def test_finding_id_is_content_and_ordinal_based():
    seen = collections.Counter()
    finding = {"b": 1, "a": 2}
    first = finding_id("layer1/x.json", finding, seen)
    second = finding_id("layer1/x.json", {"a": 2, "b": 1}, seen)
    assert first != second  # same content, next ordinal
    assert first == finding_id("layer1/x.json", finding, collections.Counter())
    assert finding_id("layer1/y.json", finding, collections.Counter()) != first
    assert finding_id("layer1/x.json", "text", collections.Counter()) == \
        finding_id("layer1/x.json", {"message": "text"}, collections.Counter())
    uuid.UUID(first)


def test_duplicate_findings_in_a_file_keep_distinct_ids(app):
    counts = import_dataset_file("pentest-findings", L1_PATH, SCAN_L1)
    assert counts.created == 3
    highs = PentestFinding.query.filter_by(severity="HIGH").all()
    assert len({f.id for f in highs}) == 2
    high = highs[0]
    assert (high.layer, high.repo, high.scan_id, high.summary) == (1, "RepoA", "scan-1", "Bad")
    assert high.source_file == "layer1/scan-1-RepoA.json"
    assert high.file_path == "package.json"
    assert high.timestamp == datetime(2026, 4, 16, 19, 34, 13)


def test_reordered_findings_keep_their_ids(app):
    import_dataset_file("pentest-findings", L1_PATH, SCAN_L1)
    db.session.commit()
    ids = {f.id for f in PentestFinding.query.all()}
    reordered = dict(SCAN_L1, findings=list(reversed(SCAN_L1["findings"])))
    with count_writes() as (writes, _):
        counts = import_dataset_file("pentest-findings", L1_PATH, reordered)
    assert (counts.created, counts.updated, counts.unchanged, counts.deleted) == (0, 0, 3, 0)
    assert sum(writes.values()) == 0
    assert {f.id for f in PentestFinding.query.all()} == ids


def test_old_id_rows_of_the_same_file_are_replaced(app):
    db.session.add_all([
        PentestFinding(id="old-1", layer=1, source_file="layer1/scan-1-RepoA.json", summary="old"),
        PentestFinding(id="other", layer=1, source_file="layer1/other.json", summary="kept"),
    ])
    db.session.commit()
    counts = import_dataset_file("pentest-findings", L1_PATH, SCAN_L1)
    db.session.commit()
    assert (counts.created, counts.deleted) == (3, 1)
    assert db.session.get(PentestFinding, "old-1") is None
    assert db.session.get(PentestFinding, "other") is not None


def test_bulk_directory_import_rebuilds_old_ids(app, repo):
    db.session.add(PentestFinding(id="old-1", layer=1, source_file="layer1/scan-1-RepoA.json"))
    db.session.commit()
    result = import_directory(str(repo), datasets=["pentest-findings"])
    assert result["datasets"]["pentest-findings"]["deleted"] == 1
    assert list(result["datasets"]) == ["pentest-findings"]
    assert PentestFinding.query.count() == 5


def test_removed_finding_is_deleted_and_changed_finding_replaced(app):
    import_dataset_file("pentest-findings", L1_PATH, SCAN_L1)
    db.session.commit()
    shorter = dict(SCAN_L1, findings=SCAN_L1["findings"][1:])
    counts = import_dataset_file("pentest-findings", L1_PATH, shorter)
    assert (counts.unchanged, counts.deleted) == (1, 1) or (counts.unchanged, counts.deleted) == (2, 1)
    assert PentestFinding.query.count() == 2

    rescanned = dict(SCAN_L1, timestamp="2026-05-01T000000Z", findings=SCAN_L1["findings"][1:])
    counts = import_dataset_file("pentest-findings", L1_PATH, rescanned)
    assert counts.updated == 2  # same findings, new scan timestamp


def test_empty_findings_list_is_authoritative(app):
    import_dataset_file("pentest-findings", L1_PATH, SCAN_L1)
    counts = import_dataset_file("pentest-findings", L1_PATH, dict(SCAN_L1, findings=[]))
    assert counts.deleted == 3


def test_layer4_structured_fields_and_bare_strings(app):
    counts = import_dataset_file("pentest-findings", "pentest-evidence/layer4/scan-4--agent.json", SCAN_L4)
    assert counts.created == 2
    medium = PentestFinding.query.filter_by(severity="MEDIUM").one()
    assert medium.remediation == json.dumps({"file": "x"}, sort_keys=True)
    assert medium.summary == str({"title": "t"})
    bare = PentestFinding.query.filter(PentestFinding.severity.is_(None)).one()
    assert bare.summary == "a bare string finding"
    assert bare.other_data == {"message": "a bare string finding"}


def test_pentest_files_without_findings_are_skipped(app):
    counts = import_dataset_file("pentest-findings", "pentest-evidence/layer1/scan-1-summary.json", SUMMARY)
    assert (counts.skipped, counts.errors) == (1, [])


@pytest.mark.parametrize("path,data,message", [
    (L1_PATH, [1, 2], "expected a JSON object"),
    (L1_PATH, {"findings": "nope"}, "findings is not a list"),
    ("pentest-evidence/scan.json", SCAN_L1, "not a pentest-evidence"),
    ("pentest-evidence/layerX/scan.json", SCAN_L1, "not a pentest-evidence"),
    ("pentest-evidence/layer1/scan.txt", SCAN_L1, "not a pentest-evidence"),
])
def test_malformed_pentest_files_are_reported(app, path, data, message):
    counts = import_dataset_file("pentest-findings", path, data)
    assert counts.skipped == 1
    assert message in counts.errors[0]


def test_pentest_value_too_long_is_skipped(app):
    scan = dict(SCAN_L1, findings=[{"severity": "S" * 60}, {"severity": "LOW"}])
    counts = import_dataset_file("pentest-findings", L1_PATH, scan)
    assert (counts.created, counts.skipped) == (1, 1)
    assert "severity is longer than 50" in counts.errors[0]


def test_pentest_source_file_variants():
    assert PentestFindingsLoader.source_file_for("layer2/x.json") == ("layer2/x.json", 2)
    assert PentestFindingsLoader.source_file_for("a/pentest-evidence/layer3/y.json") == ("layer3/y.json", 3)
    assert PentestFindingsLoader.source_file_for(".\\pentest-evidence\\layer4\\z.json") == ("layer4/z.json", 4)


def test_remove_dataset_file(app):
    import_dataset_file("pentest-findings", L1_PATH, SCAN_L1)
    db.session.commit()
    dry = remove_dataset_file("pentest-findings", L1_PATH, dry_run=True)
    assert dry.deleted == 3 and PentestFinding.query.count() == 3
    counts = remove_dataset_file("pentest-findings", L1_PATH)
    assert counts.deleted == 3 and PentestFinding.query.count() == 0
    assert remove_dataset_file("pentest-findings", L1_PATH).deleted == 0

    bad = remove_dataset_file("pentest-findings", "pentest-evidence/x.json")
    assert bad.skipped == 1

    kept = remove_dataset_file("controls", "controls.json")
    assert kept.skipped == 1 and kept.deleted == 0
    assert "records are kept" in kept.errors[0]
    with pytest.raises(ValueError):
        remove_dataset_file("nope", "x.json")


# --------------------------------------------------------------------------
# Directory import
# --------------------------------------------------------------------------

def test_import_directory_validates_arguments(app, tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        import_directory(str(tmp_path / "missing"))
    with pytest.raises(ValueError, match="unknown dataset"):
        import_directory(str(tmp_path), datasets=["controls", "bogus"])


def test_import_directory_on_empty_directory(app, tmp_path):
    messages = []
    result = import_directory(str(tmp_path), log=messages.append)
    assert result["totals"]["created"] == 0
    assert result["decision_logs"] == {"created": 0, "replaced": 0, "unchanged": 0,
                                       "kept_existing": 0, "rejected": 0, "failed": 0}
    assert any("not found" in m for m in messages)


def test_a_bad_file_is_rolled_back_alone(app, repo):
    (repo / "systems.json").write_text("{broken")
    (repo / "pentest-evidence" / "layer1" / "zz-broken.json").write_text("[")
    result = import_directory(str(repo), datasets=DATASET_ORDER)
    assert result["failed_files"] == 2
    assert result["datasets"]["systems"]["skipped"] == 1
    assert any("systems.json: not imported (ValueError" in e for e in result["errors"])
    assert Control.query.count() == 2
    assert PentestFinding.query.count() == 5
    # tests referencing the missing system are stored without it
    assert db.session.get(TestRecord, "t1").system_id is None


def test_a_database_error_rolls_back_only_that_file(app, repo, monkeypatch):
    original = evidence_import._import_parsed

    def failing(loader, path, parsed, ctx):
        if loader.dataset == "vendors":
            db.session.add(Vendor(id="v-partial", name="partial"))
            db.session.flush()
            raise RuntimeError("boom\nsecond line")
        return original(loader, path, parsed, ctx)

    monkeypatch.setattr(evidence_import, "_import_parsed", failing)
    result = import_directory(str(repo), datasets=DATASET_ORDER)
    assert result["failed_files"] == 1
    assert "vendors.json: not imported (RuntimeError: boom)" in result["errors"]
    assert db.session.get(Vendor, "v-partial") is None
    assert Evidence.query.count() == 2


def test_loader_load_wrapper_uses_the_engine(app, repo):
    from cli.loaders.pentest_findings import PentestFindingsLoader as Loader

    result = Loader().load(str(repo))
    assert (result["created"], result["skipped"]) == (5, 1)
    assert Loader().load(str(repo / "missing"))["created"] == 0


# --------------------------------------------------------------------------
# Counts and classification
# --------------------------------------------------------------------------

def test_import_counts_add_and_cap():
    a = ImportCounts(created=1, updated=2, unchanged=3, deleted=4, skipped=5)
    for n in range(99):
        a.error(f"a{n}")
    b = ImportCounts(created=10)
    b.error("b0")
    b.error("b1")
    b.errors_omitted = 7
    a.add(b)
    data = a.as_dict()
    assert (data["created"], data["updated"], data["unchanged"], data["deleted"], data["skipped"]) == (11, 2, 3, 4, 5)
    assert len(data["errors"]) == 100 and data["errors"][-1] == "b0"
    assert data["errors_omitted"] == 8


@pytest.mark.parametrize("path,authored_kind,default_kind", [
    ("controls.json", "dataset:controls", "dataset:controls"),
    ("./systems.json", "dataset:systems", "dataset:systems"),
    ("/tests.json", "dataset:tests", "dataset:tests"),
    ("policy-index.json", "dataset:policies", "dataset:policies"),
    ("vendors.json", "dataset:vendors", "dataset:vendors"),
    ("risk-register.json", "dataset:risk-register", "dataset:risk-register"),
    ("evidence/evidence-index.json", None, "dataset:evidence"),
    ("evidence/artifacts/decisions/2026-q3.md", None, None),
    ("pentest-evidence/layer3/abc-summary.json", None, "dataset:pentest-findings"),
    ("pentest-evidence/layer3/deeper/abc.json", None, None),
    ("decision-logs/2026-01-01T000000Z_abc.jsonl", None, "decision_log"),
    ("decision-logs/2026-01-01T000000Z_abc.jsonl.manifest.json", None, "decision_log"),
    ("decision-logs/2026-01-01T000000Z_abc.jsonl.part-0001", None, None),
    ("decision-logs/2026-01-01T000000Z_abc.meta.json", None, None),
    ("nested/controls.json", None, None),
    ("README.md", None, None),
])
def test_classify_path_default_and_authored_mappings(path, authored_kind, default_kind):
    """The defaults map every kind of the layout; the authored mappings (a source whose
    repository leaves pentest evidence and decision logs to the evidence store) only the
    six authored datasets."""
    assert classify_path(path) == default_kind
    assert classify_path(path, AUTHORED_EVIDENCE_MAPPINGS) == authored_kind


def test_default_mappings_read_every_kind_and_cli_import_the_authored_datasets():
    assert DEFAULT_EVIDENCE_MAPPINGS == [
        {"pattern": "controls.json", "kind": "dataset:controls"},
        {"pattern": "systems.json", "kind": "dataset:systems"},
        {"pattern": "tests.json", "kind": "dataset:tests"},
        {"pattern": "policy-index.json", "kind": "dataset:policies"},
        {"pattern": "vendors.json", "kind": "dataset:vendors"},
        {"pattern": "risk-register.json", "kind": "dataset:risk-register"},
        {"pattern": "evidence/evidence-index.json", "kind": "dataset:evidence"},
        {"pattern": "pentest-evidence/layer*/*.json", "kind": "dataset:pentest-findings"},
        {"pattern": "decision-logs/*.jsonl", "kind": "decision_log"},
        {"pattern": "decision-logs/*.jsonl.manifest.json", "kind": "decision_log"},
    ]
    assert AUTHORED_EVIDENCE_MAPPINGS == DEFAULT_EVIDENCE_MAPPINGS[:6]
    assert DEFAULT_DATASETS == ["controls", "systems", "tests", "policies", "vendors", "risk-register"]


def test_import_directory_defaults_to_the_authored_datasets(app, repo):
    write_json(repo / "decision-logs" / "2026-01-01T000000Z_s-default.jsonl",
               {"type": "user", "message": {"content": "hi"}})
    result = import_directory(str(repo))
    assert list(result["datasets"]) == ["controls", "systems", "tests", "policies", "vendors", "risk-register"]
    assert result["errors"] == [] and result["failed_files"] == 0
    assert (Evidence.query.count(), PentestFinding.query.count(), DecisionLogSession.query.count()) == (0, 0, 0)
    assert result["decision_logs"]["created"] == 0

    named = import_directory(str(repo), datasets=["evidence", "pentest-findings"], include_decision_logs=True)
    assert list(named["datasets"]) == ["evidence", "pentest-findings"]
    assert (Evidence.query.count(), PentestFinding.query.count(), DecisionLogSession.query.count()) == (2, 5, 1)
    assert named["decision_logs"]["created"] == 1


def test_classify_path_custom_mappings():
    mappings = [
        ("compliance/**/controls.json", "dataset:controls"),
        {"pattern": "logs/[!x]?.jsonl", "kind": "decision_log"},
        {"pattern": "data/[ab]*.json", "kind": "dataset:systems"},
        {"pattern": "weird[", "kind": "literal"},
    ]
    assert classify_path("compliance/controls.json", mappings) == "dataset:controls"
    assert classify_path("compliance/a/b/controls.json", mappings) == "dataset:controls"
    assert classify_path("logs/ab.jsonl", mappings) == "decision_log"
    assert classify_path("logs/xb.jsonl", mappings) is None
    assert classify_path("data/b1.json", mappings) == "dataset:systems"
    assert classify_path("data/c1.json", mappings) is None
    assert classify_path("weird[", mappings) == "literal"
    assert len(DEFAULT_EVIDENCE_MAPPINGS) == 10


# --------------------------------------------------------------------------
# Decision logs
# --------------------------------------------------------------------------

def _line(kind, text, ts, **extra):
    record = {"type": kind, "timestamp": ts,
              "message": {"role": kind, "content": [{"type": "text", "text": text}], "id": f"m-{ts}"}}
    record.update(extra)
    return json.dumps(record)


def transcript(n, prefix="msg"):
    lines = [_line("user", f"{prefix} 0", "2026-03-16T12:00:00Z", cwd="/w", gitBranch="main")]
    for i in range(1, n):
        lines.append(_line("assistant" if i % 2 else "user", f"{prefix} {i}", f"2026-03-16T12:00:{i:02d}Z"))
    return ("\n".join(lines) + "\n").encode()


def test_decision_log_created_unchanged_replaced_kept(app):
    first = import_decision_log(transcript(3), session_id="s-1", source_path="decision-logs/a_s-1.jsonl",
                                exit_reason="clear")
    db.session.commit()
    assert (first.status, first.entries, first.content_bytes) == ("created", 3, len(transcript(3)))
    session = db.session.get(DecisionLogSession, "s-1")
    assert (session.content_sha256, session.exit_reason, session.cwd) == (first.content_sha256, "clear", "/w")
    assert session.transcript_path == "decision-logs/a_s-1.jsonl"

    with count_writes() as (writes, _):
        again = import_decision_log(transcript(3), session_id="s-1")
    assert (again.status, again.entries) == ("unchanged", 3)
    assert sum(writes.values()) == 0

    first_ids = [e.id for e in DecisionLogEntry.query.filter_by(session_id="s-1").order_by(DecisionLogEntry.id)]
    longer = import_decision_log(transcript(5), session_id="s-1", submitted_by=None)
    db.session.commit()
    assert (longer.status, longer.entries) == ("replaced", 5)
    session = db.session.get(DecisionLogSession, "s-1")
    assert session.content_bytes == len(transcript(5))
    assert session.replaced_at is not None
    assert session.exit_reason == "clear"  # kept when the new export has none
    entries = DecisionLogEntry.query.filter_by(session_id="s-1").order_by(DecisionLogEntry.id).all()
    assert len(entries) == 5
    assert [e.id for e in entries[:3]] == first_ids  # the stored prefix stays; two are appended
    assert [e.content_text for e in entries] == [f"msg {i}" for i in range(5)]

    with count_writes() as (writes, _):
        shorter = import_decision_log(transcript(4), session_id="s-1")
    assert (shorter.status, shorter.entries) == ("kept_existing", 5)
    assert sum(writes.values()) == 0

    with count_writes() as (writes, statements):
        different = import_decision_log(transcript(4, prefix="other"), session_id="s-1")
    db.session.commit()
    assert (different.status, different.entries) == ("rejected", 5)
    assert different.reason.startswith("entry 1 differs from the stored transcript")
    assert writes == {"INSERT": 1} and "decision_log_transcripts" in statements[0]
    assert [e.content_text for e in DecisionLogEntry.query.filter_by(session_id="s-1")] == \
        [f"msg {i}" for i in range(5)]


def test_decision_log_dry_run(app):
    with count_writes() as (writes, _):
        result = import_decision_log(transcript(2), session_id="s-dry", dry_run=True)
    assert result.status == "created" and sum(writes.values()) == 0
    import_decision_log(transcript(2), session_id="s-dry")
    with count_writes() as (writes, _):
        assert import_decision_log(transcript(4), session_id="s-dry", dry_run=True).status == "replaced"
    assert sum(writes.values()) == 0


def test_decision_log_session_id_rules(app):
    assert import_decision_log(transcript(1), source_path="x/2026-01-01T000000Z_abc-1.jsonl").session_id == "abc-1"
    manifest_name = "2026-01-01T000000Z_abc-2.jsonl.manifest.json"
    assert import_decision_log(transcript(1), source_path=manifest_name).session_id == "abc-2"
    assert import_decision_log("text content\n", session_id="abc-3").status == "created"
    with pytest.raises(ValueError, match="cannot determine"):
        import_decision_log(transcript(1), source_path="no-session.jsonl")
    with pytest.raises(ValueError, match="cannot determine"):
        import_decision_log(transcript(1))
    with pytest.raises(ValueError, match="cannot determine"):
        import_decision_log(transcript(1), source_path="a_b.txt")
    with pytest.raises(ValueError, match="invalid session id"):
        import_decision_log(transcript(1), session_id="../../etc")
    with pytest.raises(TypeError):
        import_decision_log(12345, session_id="abc-4")


def _legacy_session(sid, content):
    """Store a session the way the pre-digest ingest did (no sha/bytes)."""
    import_decision_log(content, session_id=sid)
    session = db.session.get(DecisionLogSession, sid)
    session.content_sha256 = None
    session.content_bytes = None
    db.session.commit()


def test_legacy_identical_transcript_is_backfilled(app):
    _legacy_session("legacy-1", transcript(3))
    with count_writes() as (writes, statements):
        result = import_decision_log(transcript(3), session_id="legacy-1")
    db.session.commit()
    assert (result.status, result.entries) == ("unchanged", 3)
    assert writes == {"UPDATE": 1}
    assert "decision_log_sessions" in statements[0]
    session = db.session.get(DecisionLogSession, "legacy-1")
    assert session.content_sha256 == result.content_sha256
    assert session.content_bytes == len(transcript(3))

    with count_writes() as (writes, _):
        assert import_decision_log(transcript(3), session_id="legacy-1").status == "unchanged"
    assert sum(writes.values()) == 0


def test_legacy_longer_transcript_replaces(app):
    _legacy_session("legacy-2", transcript(3))
    result = import_decision_log(transcript(4), session_id="legacy-2")
    assert (result.status, result.entries) == ("replaced", 4)
    assert db.session.get(DecisionLogSession, "legacy-2").content_sha256 == result.content_sha256


def test_legacy_shorter_transcript_is_kept(app):
    _legacy_session("legacy-3", transcript(3))
    with count_writes() as (writes, _):
        result = import_decision_log(transcript(2), session_id="legacy-3")
    assert (result.status, result.entries) == ("kept_existing", 3)
    assert sum(writes.values()) == 0
    assert db.session.get(DecisionLogSession, "legacy-3").content_sha256 is None


def test_legacy_different_transcript_is_rejected(app):
    _legacy_session("legacy-6", transcript(3))
    result = import_decision_log(transcript(3, prefix="different"), session_id="legacy-6")
    db.session.commit()
    assert (result.status, result.entries) == ("rejected", 3)
    session = db.session.get(DecisionLogSession, "legacy-6")
    assert session.content_sha256 is None
    assert [e.content_text for e in session.interactions] == ["msg 0", "msg 1", "msg 2"]


def test_legacy_backfill_dry_run_writes_nothing(app):
    _legacy_session("legacy-4", transcript(3))
    with count_writes() as (writes, _):
        assert import_decision_log(transcript(3), session_id="legacy-4", dry_run=True).status == "unchanged"
        assert import_decision_log(transcript(5), session_id="legacy-4", dry_run=True).status == "replaced"
    assert sum(writes.values()) == 0


def test_legacy_timestamps_compare_as_utc(app):
    content = (_line("user", "hi", "2026-03-16T08:00:00-04:00") + "\n").encode()
    _legacy_session("legacy-5", content)
    assert import_decision_log(content, session_id="legacy-5").status == "unchanged"


def _write_chunked(directory, name, data, part_size):
    manifest_bytes, parts = chunked_files.split(name, data, part_size=part_size)
    for part_name, chunk in parts:
        (directory / part_name).write_bytes(chunk)
    (directory / (name + chunked_files.MANIFEST_SUFFIX)).write_bytes(manifest_bytes)


def test_import_directory_decision_logs(app, tmp_path):
    logs = tmp_path / "decision-logs"
    logs.mkdir()
    # a resumed session with two growing exports: the larger one wins
    (logs / "2026-03-01T000000Z_sess-a.jsonl").write_bytes(transcript(2))
    (logs / "2026-03-02T000000Z_sess-a.jsonl").write_bytes(transcript(4))
    (logs / "2026-03-02T000000Z_sess-a.meta.json").write_text(json.dumps({"reason": "logout"}))
    (logs / "2026-03-01T000000Z_sess-a.meta.json").write_text(json.dumps({"reason": "clear"}))
    # a large transcript stored in chunks, plus an older smaller plain export
    big = transcript(40)
    _write_chunked(logs, "2026-03-05T000000Z_sess-b.jsonl", big, part_size=1000)
    (logs / "2026-03-04T000000Z_sess-b.jsonl").write_bytes(transcript(3))
    (logs / "2026-03-05T000000Z_sess-b.meta.json").write_text("not json")
    # a corrupted chunked transcript
    _write_chunked(logs, "2026-03-06T000000Z_sess-c.jsonl", transcript(30), part_size=1000)
    (logs / "2026-03-06T000000Z_sess-c.jsonl.part-0002").write_bytes(b"x" * 1000)
    # an unreadable manifest, a file without a session id, unrelated files
    (logs / "2026-03-07T000000Z_sess-d.jsonl.manifest.json").write_text("{}")
    (logs / "stray.jsonl").write_bytes(transcript(1))
    (logs / "notes.txt").write_text("ignored")
    (logs / "subdir").mkdir()

    result = import_directory(str(tmp_path), include_decision_logs=True)
    assert result["decision_logs"] == {"created": 2, "replaced": 0, "unchanged": 0,
                                       "kept_existing": 0, "rejected": 0, "failed": 2}
    assert result["failed_files"] == 2
    joined = "\n".join(result["errors"])
    assert "sess-c.jsonl: not imported (ChunkedFileError" in joined
    assert "sess-d.jsonl.manifest.json: not imported" in joined
    assert "stray.jsonl: no session id" in joined

    session_a = db.session.get(DecisionLogSession, "sess-a")
    assert session_a.content_bytes == len(transcript(4))
    assert session_a.exit_reason == "logout"
    assert session_a.transcript_path == "decision-logs/2026-03-02T000000Z_sess-a.jsonl"
    session_b = db.session.get(DecisionLogSession, "sess-b")
    assert session_b.content_bytes == len(big)
    assert session_b.exit_reason is None
    assert DecisionLogEntry.query.filter_by(session_id="sess-b").count() == 40

    with count_writes() as (writes, _):
        rerun = import_directory(str(tmp_path), include_decision_logs=True)
    assert rerun["decision_logs"]["unchanged"] == 2
    assert sum(writes.values()) == 0

    dry = import_directory(str(tmp_path), dry_run=True, include_decision_logs=True)
    assert dry["decision_logs"]["unchanged"] == 2


def test_decision_log_database_failure_is_isolated(app, tmp_path, monkeypatch):
    from app.services import evidence_import_decision_logs as dl

    logs = tmp_path / "decision-logs"
    logs.mkdir()
    (logs / "2026-03-01T000000Z_ok.jsonl").write_bytes(transcript(2))
    (logs / "2026-03-02T000000Z_bad.jsonl").write_bytes(transcript(2))
    original = dl.import_decision_log

    def flaky(content, **kwargs):
        if kwargs["session_id"] == "bad":
            raise RuntimeError("database went away")
        return original(content, **kwargs)

    monkeypatch.setattr(dl, "import_decision_log", flaky)
    result = import_directory(str(tmp_path), include_decision_logs=True)
    assert result["decision_logs"]["created"] == 1
    assert result["decision_logs"]["failed"] == 1
    assert "RuntimeError: database went away" in result["errors"][0]


def test_describe_exception_uses_driver_message_only():
    class Wrapped(Exception):
        orig = ValueError("driver says no\nDETAIL: Key (id)=(secret) already exists")

    assert evidence_import.describe_exception(Wrapped("SQL with params")) == "Wrapped: driver says no"
    assert evidence_import.describe_exception(RuntimeError("")) == "RuntimeError: "


def test_manifest_naming_another_file_is_rejected(app, tmp_path):
    logs = tmp_path / "decision-logs"
    logs.mkdir()
    manifest_bytes, _ = chunked_files.split("2026-01-01T000000Z_other.jsonl", transcript(2), part_size=100)
    (logs / "2026-01-01T000000Z_sess-x.jsonl.manifest.json").write_bytes(manifest_bytes)
    result = import_directory(str(tmp_path), include_decision_logs=True)
    assert result["decision_logs"]["failed"] == 1
    assert "manifest names" in result["errors"][0]


def test_import_context_tracks_created_ids(app):
    import_dataset_file("controls", "controls.json", CONTROLS)
    ctx = evidence_import.ImportContext()
    assert ctx.ids(Control) == {"c1", "c2"}
    ctx.note_created(Control, "c3")
    assert "c3" in ctx.ids(Control)
    ctx.after_rollback()
    assert ctx.ids(Control) == {"c1", "c2"}

    dry = evidence_import.ImportContext(dry_run=True)
    dry.note_created(Control, "c9")
    dry.after_rollback()
    assert "c9" in dry.ids(Control)


def test_custom_loader_returning_no_record_is_skipped(app, tmp_path):
    from cli.loaders.controls import ControlsLoader

    class PickyLoader(ControlsLoader):
        def _build_record(self, item):
            return None if item.get("skip") else super()._build_record(item)

    write_json(tmp_path / "controls.json", [dict(CONTROLS[1], skip=True), CONTROLS[0]])
    result = PickyLoader().load(str(tmp_path))
    assert (result["created"], result["skipped"]) == (1, 1)
    assert "could not be built" in result["errors"][0]


def test_double_star_without_slash():
    assert classify_path("logs/a/b/c.txt", [("logs/**", "any")]) == "any"
    assert classify_path("other/c.txt", [("logs/**", "any")]) is None


# --------------------------------------------------------------------------
# Pentest namespaces (red-team finding 15a)
# --------------------------------------------------------------------------

def _scan(summary):
    return {"scan_id": "s", "findings": [{"summary": summary, "severity": "HIGH"}]}


def test_namespaced_sources_never_touch_each_others_findings(app):
    import_dataset_file("pentest-findings", L1_PATH, _scan("from A"), namespace="source-a")
    db.session.commit()
    counts = import_dataset_file("pentest-findings", L1_PATH, _scan("from B"), namespace="source-b")
    db.session.commit()
    assert (counts.created, counts.updated, counts.deleted) == (1, 0, 0)
    rows = {f.source_file: f for f in PentestFinding.query.all()}
    assert set(rows) == {"source-a:layer1/scan-1-RepoA.json", "source-b:layer1/scan-1-RepoA.json"}
    assert rows["source-a:layer1/scan-1-RepoA.json"].summary == "from A"

    # Identical findings in two sources get distinct ids, so neither updates the other's row.
    same = import_dataset_file("pentest-findings", L1_PATH, _scan("from A"), namespace="source-b")
    db.session.commit()
    assert (same.created, same.deleted) == (1, 1)
    assert sorted(f.summary for f in PentestFinding.query.all()) == ["from A", "from A"]

    removed = remove_dataset_file("pentest-findings", L1_PATH, namespace="source-b")
    db.session.commit()
    assert removed.deleted == 1
    assert [f.source_file for f in PentestFinding.query.all()] == ["source-a:layer1/scan-1-RepoA.json"]


def test_namespaced_import_takes_over_cli_import_findings_of_the_same_path(app):
    import_dataset_file("pentest-findings", L1_PATH, SCAN_L1)  # cli import: no namespace
    import_dataset_file("pentest-findings", "pentest-evidence/layer1/other.json", _scan("other file"))
    db.session.commit()
    counts = import_dataset_file("pentest-findings", L1_PATH, SCAN_L1, namespace="src")
    db.session.commit()
    assert (counts.created, counts.deleted) == (3, 3)
    by_file = collections.Counter(f.source_file for f in PentestFinding.query.all())
    assert by_file == {"src:layer1/scan-1-RepoA.json": 3, "layer1/other.json": 1}

    # A namespace-less (cli) import never deletes namespaced findings.
    import_dataset_file("pentest-findings", L1_PATH, dict(SCAN_L1, findings=[]))
    db.session.commit()
    assert PentestFinding.query.filter_by(source_file="src:layer1/scan-1-RepoA.json").count() == 3

    import_dataset_file("pentest-findings", "pentest-evidence/layer1/other.json", _scan("other file"))
    db.session.commit()
    assert remove_dataset_file("pentest-findings", "pentest-evidence/layer1/other.json",
                               namespace="src").deleted == 1


def test_is_deadlock():
    class DriverError(Exception):
        pgcode = "40P01"

    assert is_deadlock(OperationalError("UPDATE x", {}, DriverError()))
    assert is_deadlock(DriverError())
    assert not is_deadlock(OperationalError("UPDATE x", {}, Exception("other")))
    assert not is_deadlock(ValueError("x"))


# --------------------------------------------------------------------------
# Decision-log versions and the extension rule (red-team finding 5)
# --------------------------------------------------------------------------

def _versions(sid):
    return (DecisionLogTranscript.query.filter_by(session_id=sid)
            .order_by(DecisionLogTranscript.received_at, DecisionLogTranscript.status).all())


def _stored(sid):
    return [(e.role, e.content_text, e.tool_calls, e.message_id, e.is_verification)
            for e in DecisionLogEntry.query.filter_by(session_id=sid).order_by(DecisionLogEntry.id)]


RICH_TRANSCRIPT = "\n".join(json.dumps(record) for record in [
    {"type": "user", "timestamp": "2026-03-16T08:00:00-04:00", "cwd": "/work", "gitBranch": "dev",
     "message": {"role": "user", "id": "u1", "content": "Please deploy ☃"}},
    {"type": "assistant", "timestamp": "2026-03-16T12:00:01.250Z",
     "message": {"role": "assistant", "id": "a1", "model": "model-x",
                 "content": [{"type": "text", "text": "Running"},
                             {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}}]}},
    {"type": "assistant", "message": {"role": "assistant",
                                      "content": [{"type": "tool_use", "name": "Read", "input": {}}]}},
    {"type": "user", "timestamp": 1773662460000, "message": {"role": "user", "content": [
        {"type": "text", "text": "done."}]}},
    {"type": "summary", "summary": "not an entry"},
]).encode()


def test_versions_created_extended_and_superseded_content_is_kept(app):
    agent = team_service.create_member("Agent", "agent@example.com", "agent")
    other = team_service.create_member("Other", "other@example.com", "agent")
    import_decision_log(RICH_TRANSCRIPT, session_id="v-1", source_path="uploads/v-1.jsonl",
                        submitted_by=agent.id)
    db.session.commit()
    (current,) = _versions("v-1")
    assert (current.status, current.entry_count, current.content_gz) == ("current", 4, None)
    assert current.content_sha256 == evidence_import_sha(RICH_TRANSCRIPT)
    assert (current.source_path, current.submitted_by) == ("uploads/v-1.jsonl", agent.id)
    first_entries = _stored("v-1")

    extra = json.dumps({"type": "assistant", "timestamp": "2026-03-16T12:05:00Z",
                        "message": {"role": "assistant", "id": "a9", "content": "later"}}).encode()
    longer = RICH_TRANSCRIPT + b"\n" + extra
    assert import_decision_log(longer, session_id="v-1", submitted_by=other.id).status == "replaced"
    db.session.commit()
    superseded, new_current = sorted(_versions("v-1"), key=lambda v: v.status != "superseded")
    assert (superseded.status, superseded.id) == ("superseded", current.id)
    assert superseded.content_sha256 == evidence_import_sha(RICH_TRANSCRIPT)
    assert superseded.reason == "superseded by a longer export that extends it"
    assert (new_current.status, new_current.entry_count, new_current.submitted_by) == ("current", 5, other.id)
    assert db.session.get(DecisionLogSession, "v-1").submitted_by == agent.id  # the first submitter

    # The superseded content is a reconstruction that parses back to exactly the old entries.
    text = gzip.decompress(superseded.content_gz)
    header = json.loads(text.splitlines()[0])
    assert header == {"type": "decision-log-reconstruction", "format": "decision-log-reconstruction/v1",
                      "session_id": "v-1", "content_sha256": evidence_import_sha(RICH_TRANSCRIPT),
                      "content_bytes": len(RICH_TRANSCRIPT), "entries": 4}
    reparsed = parse_transcript(text)
    original = parse_transcript(RICH_TRANSCRIPT)
    assert reparsed.entries == original.entries
    assert (reparsed.model, reparsed.cwd, reparsed.git_branch) == ("model-x", "/work", "dev")
    assert _stored("v-1")[:4] == first_entries


def evidence_import_sha(content):
    import hashlib

    return hashlib.sha256(content).hexdigest()


def test_rejected_upload_is_recorded_once_and_changes_nothing(app):
    import_decision_log(transcript(3), session_id="v-2")
    db.session.commit()
    before = _stored("v-2")
    forged = transcript(5, prefix="forged")
    first = import_decision_log(forged, session_id="v-2", source_path="x/forged.jsonl")
    db.session.commit()
    assert (first.status, first.entries) == ("rejected", 3)
    rejected = [v for v in _versions("v-2") if v.status == "rejected"]
    assert len(rejected) == 1
    assert gzip.decompress(rejected[0].content_gz) == forged
    assert (rejected[0].entry_count, rejected[0].source_path) == (5, "x/forged.jsonl")
    assert rejected[0].reason == first.reason
    assert _stored("v-2") == before
    session = db.session.get(DecisionLogSession, "v-2")
    assert session.content_sha256 == evidence_import_sha(transcript(3))

    with count_writes() as (writes, _):
        again = import_decision_log(forged, session_id="v-2")
    assert again.status == "rejected" and sum(writes.values()) == 0

    # A longer transcript that keeps the stored entries but changes a later one is rejected too.
    tampered = transcript(3) + transcript(4, prefix="msg").splitlines(keepends=True)[3]
    assert import_decision_log(tampered, session_id="v-2").status == "replaced"
    rewritten = transcript(2) + b"\n".join(transcript(5, prefix="edited").splitlines()[2:]) + b"\n"
    result = import_decision_log(rewritten, session_id="v-2")
    assert result.status == "rejected" and result.reason.startswith("entry 3 differs")


def test_longer_garbage_never_wipes_a_transcript(app):
    import_decision_log(transcript(2), session_id="v-3")
    db.session.commit()
    with count_writes() as (writes, _):
        result = import_decision_log(b"not json\n" * 200, session_id="v-3")
    assert (result.status, result.entries) == ("kept_existing", 2)
    assert sum(writes.values()) == 0
    assert DecisionLogEntry.query.filter_by(session_id="v-3").count() == 2


def test_extending_a_session_without_version_rows_records_the_previous_version(app):
    _legacy_session("legacy-7", transcript(2))
    DecisionLogTranscript.query.filter_by(session_id="legacy-7").delete()
    session = db.session.get(DecisionLogSession, "legacy-7")
    session.content_sha256 = "ab" * 32
    session.content_bytes = 123
    db.session.commit()
    assert import_decision_log(transcript(3), session_id="legacy-7").status == "replaced"
    db.session.commit()
    statuses = {v.status: v for v in _versions("legacy-7")}
    assert set(statuses) == {"superseded", "current"}
    assert (statuses["superseded"].content_sha256, statuses["superseded"].content_bytes) == ("ab" * 32, 123)
    assert parse_transcript(gzip.decompress(statuses["superseded"].content_gz)).entries == \
        parse_transcript(transcript(2)).entries


def test_dry_run_rejection_writes_nothing(app):
    import_decision_log(transcript(2), session_id="v-4")
    db.session.commit()
    with count_writes() as (writes, _):
        assert import_decision_log(transcript(3, prefix="x"), session_id="v-4", dry_run=True).status == "rejected"
    assert sum(writes.values()) == 0


def test_import_directory_reports_rejected_transcripts(app, tmp_path):
    import_decision_log(transcript(3), session_id="sess-r")
    db.session.commit()
    logs = tmp_path / "decision-logs"
    logs.mkdir()
    (logs / "2026-03-01T000000Z_sess-r.jsonl").write_bytes(transcript(4, prefix="forged"))
    result = import_directory(str(tmp_path), include_decision_logs=True)
    assert result["decision_logs"]["rejected"] == 1
    assert result["failed_files"] == 1
    assert any("sess-r.jsonl: rejected (entry 1 differs" in line for line in result["errors"])
    db.session.expire_all()
    assert DecisionLogTranscript.query.filter_by(session_id="sess-r", status="rejected").count() == 1
