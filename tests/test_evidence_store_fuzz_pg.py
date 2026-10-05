"""Evidence store fuzzing: randomised hostile JSON values, member names, dates
and numbers through the pure content checks, and through a sync and its
verification.

The content checks raise nothing but their own refusals; a sync never fails
to write content its check passed (no ``error`` record, no run error); and
verification re-derives every outcome the sync recorded (status ``valid``,
with ``full``). The random generator is seeded, so a failure reproduces."""

import collections
import json
import random

import pytest

from app.models import db
from app.models.evidence_store import EvidenceStoreObject
from app.services import evidence_import
from app.services.evidence_store import plans
from tests.test_evidence_store_hardening_pg import _failures, _verify
from tests.test_evidence_store_pg import run_sync, s3  # noqa: F401
from tests.test_round2_git import GENUINE

SEED = 20261004
BENIGN_TEXT = ["", "plain", "CC7.1", "HIGH", "low", "src/app.py", "Fix it.", "été", "😀", "2026"]
HOSTILE_TEXT = ["a\x00b", "\x00", "\ud800", "x\udfffy", "\udc00\ud800", "s" * 37, "s" * 260, "s" * 1001,
                "\\u0000", " ", "﻿", "%00", "evidence-store:x", "' OR 1=1 --", "\u0000\ud800"]
DATES = ["0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00", "0001-01-01T00:00:00", "9999-12-31T23:59:59",
         "2026-04-16T193413Z", "2026-02-30", "2026-01-01", "2026-01-01T00:00:00+23:59", "not a date", "",
         "\ud800", "2026-03-16T12:00:00Z", "0000-01-01T00:00:00Z", "+275760-09-13T00:00:00Z"]
NUMBERS = [0, -1, 2 ** 31, -2 ** 31 - 1, 2 ** 63, 10 ** 300, 1e308, -1e308, 5e-324, 1.5, float("nan"), float("inf"),
           float("-inf"), True, False]


def _text(rng, level):
    return rng.choice(HOSTILE_TEXT if rng.random() < level else BENIGN_TEXT)


def _value(rng, level, depth=0):
    choice = rng.random()
    if depth >= 3 or choice < 0.4:
        return _text(rng, level)
    if choice < 0.6:
        return rng.choice(NUMBERS if rng.random() < level * 2 else [0, 1, 2, 3.5, 2 ** 63, 10 ** 300])
    if choice < 0.65:
        return None
    if choice < 0.82:
        return [_value(rng, level, depth + 1) for _ in range(rng.randint(0, 3))]
    return {_text(rng, level): _value(rng, level, depth + 1) for _ in range(rng.randint(0, 3))}


def _finding(rng, level):
    if rng.random() < 0.1:
        return _value(rng, level)
    finding = {}
    for name in ("severity", "summary", "remediation", "soc2_controls", "file_path", "message", "vulnerability",
                 "finding", "dependency"):
        if rng.random() < 0.45:
            finding[name] = _value(rng, level)
    for _ in range(rng.randint(0, 2)):
        finding[_text(rng, level)] = _value(rng, level)
    return finding


def hostile_pentest(rng):
    """A pentest file's JSON text (ASCII escapes for every non-ASCII character), hostile at a random level."""
    level = rng.choice([0.0, 0.0, 0.03, 0.3])
    body = {}
    if rng.random() < 0.85:
        body["findings"] = [_finding(rng, level) for _ in range(rng.randint(0, 4))]
    elif rng.random() < 0.5:
        body["findings"] = _value(rng, level)
    for name in ("scan_id", "repo", "repo_name"):
        if rng.random() < 0.4:
            body[name] = _value(rng, level)
    if rng.random() < 0.7:
        body["timestamp"] = rng.choice(DATES + [0, 2 ** 63, 1.5, None])
    if rng.random() < 0.04:
        body = _value(rng, level)
    return json.dumps(body).encode("ascii")


def hostile_transcript(rng):
    """A transcript of hostile records (and the odd unparseable line)."""
    level = rng.choice([0.0, 0.3, 1.0])
    lines = list(GENUINE[:rng.randint(0, 3)])
    for index in range(rng.randint(0, 3)):
        message = {"role": rng.choice(["user", "assistant", _text(rng, level)]),
                   "id": _value(rng, level) if rng.random() < level * 0.3 else f"m{index}",
                   "content": [{"type": "text", "text": _text(rng, level)}]}
        if rng.random() < 0.3:
            message["model"] = _value(rng, level) if rng.random() < level else _text(rng, level)
        record = {"type": rng.choice(["user", "assistant", "summary"]), "message": message,
                  "timestamp": rng.choice(DATES)}
        for name in ("cwd", "gitBranch"):
            if rng.random() < 0.2:
                record[name] = _value(rng, level) if rng.random() < level else _text(rng, level)
        lines.append(json.dumps(record))
    if rng.random() < 0.1:
        lines.append("{not json")
    return ("\n".join(lines) + "\n").encode("ascii")


def hostile_sidecar(rng):
    return json.dumps({"reason": _value(rng, 0.5), "agent": _value(rng, 0.5)}).encode("ascii")


def test_the_content_checks_raise_only_their_refusals():
    rng = random.Random(SEED)
    outcomes = collections.Counter()
    for index in range(3000):
        body = json.loads(hostile_pentest(rng))
        try:
            checked = plans.check_pentest(f"pentest-evidence/layer{index % 9 + 1}/f.json", body, f"v{index}")
        except plans.ContentRejected:
            outcomes["refused"] += 1
            continue
        outcomes["checked"] += 1
        for row in checked.rows or ():
            assert all(evidence_import.unstorable_value(column, row[column.key]) is None
                       for column in plans_columns("pentest_findings") if column.key in row)
    for index in range(1500):
        reason, agent = json.loads(hostile_sidecar(rng)).values()
        try:
            checked = plans.check_decision_log(hostile_transcript(rng),
                                               f"decision-logs/2026-10-01T000000Z_s{index}.jsonl", reason, agent)
        except plans.ContentRejected:
            outcomes["refused_log"] += 1
            continue
        outcomes["checked_log"] += 1
        assert checked.exit_reason is None or evidence_import.unstorable_value(
            plans_columns("decision_log_sessions", "exit_reason"), checked.exit_reason) is None
        assert checked.exit_reason is None or len(checked.exit_reason) <= 50
    assert min(outcomes.values()) > 50, outcomes  # every path is exercised


def plans_columns(table, column=None):
    """The columns of ``table`` (one column when ``column`` is named)."""
    columns = db.metadata.tables[table].columns
    return columns[column] if column else list(columns)


@pytest.mark.parametrize("seed", [SEED, SEED + 1])
def test_a_sync_of_hostile_objects_records_what_verification_rederives(pg_app, s3, seed):
    rng = random.Random(seed)
    for index in range(40):
        key = f"pentest-evidence/layer{index % 9 + 1}/fuzz-{index % 30}.json"
        body = hostile_pentest(rng)
        if index % 7 == 0:  # another source holds some paths, identically or not
            try:
                held = body if index % 2 else hostile_pentest(rng)
                evidence_import.import_dataset_file("pentest-findings", key, held, namespace="git-src")
                db.session.commit()
            except Exception:  # noqa: BLE001 - what a git import makes of hostile content is not under test
                db.session.rollback()
        s3.put(key if index < 30 else f"pentest-evidence/layer{index % 9 + 1}/fuzz-more-{index}.json", body)
    for index in range(24):
        stem = f"decision-logs/2026-10-01T{index:02d}0000Z_fz-{index % 5}"
        if rng.random() < 0.5:
            s3.put(stem + ".meta.json", hostile_sidecar(rng))
        s3.put(stem + ".jsonl", hostile_transcript(rng))
    run = run_sync()
    assert run.counts["errors"] == 0, run.details["errors"][:5]
    statuses = collections.Counter(row.status for row in EvidenceStoreObject.query)
    assert "error" not in statuses, statuses
    assert statuses["rejected"] and statuses["ingested"] and statuses["unchanged"], statuses
    for full in (False, True):
        result = _verify(s3, full=full)
        assert result["status"] == "valid", _failures(result)[:5]
    assert run_sync().counts["new"] == 0  # nothing is read again
