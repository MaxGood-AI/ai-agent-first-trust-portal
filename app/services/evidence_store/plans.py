"""What an evidence-store import does with a version's body, decided before
any write and re-derived by verification with the same functions and the
same inputs.

Every store import runs in two steps:

1. A PURE, TOTAL content check (:func:`check_pentest`,
   :func:`check_decision_log`): from the body (and, for a decision log, the
   agent and exit reason its metadata or sidecar supplies) alone, it either
   returns exactly what the import writes or raises :class:`ContentRejected`
   (:class:`TooLarge` for a decision log over a transcript limit) - never
   anything else: an unexpected error inside it is a refusal too, naming the
   error's class. It refuses or cleans everything the database could refuse:
   text holding a NUL character or an unpaired surrogate (in any string,
   JSON member names included), a non-finite number, a date-time whose UTC
   instant falls outside the years 1 to 9999, a value of a type its column
   does not take; a value longer than its column skips the finding (pentest
   evidence, as every pentest import does) or refuses the transcript
   (decision logs), and the decision-log exit reason is cleaned (NUL
   characters and unpaired surrogates replaced by U+FFFD) and cut to its
   column.
2. A plan against the database (:func:`plan_pentest`,
   :func:`plan_decision_log`): import, ``unchanged``, ``duplicate``, or a
   :class:`Conflict` (``rejected``, detail ``conflict: ...``) with what the
   database already holds. A failure while WRITING after a passing check is
   never a refusal of the content: the version stays ``error`` and every
   sync tries it again (``app.services.evidence_store.sync``).

Pentest evidence in the store's namespace
-----------------------------------------
The store's findings of ``pentest-evidence/layer<N>/<name>.json`` are stored
under ``source_file`` ``evidence-store:layer<N>/<name>.json`` and each id
derives from that ``source_file``, the object's S3 VERSION ID (unpredictable
before the upload), the finding's canonical SHA-256 and its ordinal
(:func:`store_finding_id`), so no other writer can hold an id the store will
use before the object exists. The import only INSERTS rows: it never takes
over, moves or changes a row. A set of findings is compared, in every
namespace, by its content (``evidence_import.identity_digest`` of each
finding's SHA-256 and ordinal), never by ids.

The store's namespace holds, for a path, the findings that one store object
imported: its BACKING record (an ``ingested`` record of that key whose
``import_info`` says it stored them, or such a record since erased).
Store-namespace rows no backing record accounts for are not the store's:
the plan ignores them, so they never suppress an import, and verification
fails them. The plan of a file with findings, in order:

- no findings list, or an empty one: ``unchanged``;
- the path has a backing record: ``unchanged`` when it imported exactly
  these findings, else a :class:`Conflict` (the store never replaces its
  findings);
- another namespace holds exactly these findings: ``duplicate`` of it;
- a stored row already holds one of the ids the import would insert: a
  :class:`Conflict` (the store never takes over a row);
- otherwise ``import`` (when other namespaces hold different findings for
  the path, both are kept and the sync lists the conflict).
"""

from __future__ import annotations

import collections
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

UNCHANGED = "unchanged"
DUPLICATE = "duplicate"
IMPORT = "import"
CONFLICT = "conflict"
STORE_ID_NAMESPACE = uuid.UUID("5f0c3b52-8d1e-4f7a-9c2b-6e4d8a1f0b37")
PENTEST_PREFIX = "pentest-evidence/"
_CHUNK = 500


class ContentRejected(ValueError):
    """A version's content is refused, deterministically (the message says why)."""


class TooLarge(ContentRejected):
    """A transcript over a decision-log limit (recorded ``too_large``)."""


class Conflict(ContentRejected):
    """The import would replace or take over what the database already holds
    (recorded ``rejected``, detail ``conflict: ...``)."""


def _total(check, *args):
    """Run a pure check, turning any error it raises but its own refusals into a refusal."""
    from cli.loaders.base import SkipRecord

    try:
        return check(*args)
    except ContentRejected:
        raise
    except SkipRecord as exc:
        raise ContentRejected(str(exc)) from None
    except MemoryError:
        raise
    except RecursionError:
        raise ContentRejected("nested too deeply to check") from None
    except Exception as exc:  # noqa: BLE001 - total: every input maps to an outcome
        raise ContentRejected(f"the content cannot be checked ({type(exc).__name__})") from None


# ----------------------------------------------------------------------------
# Pentest evidence
# ----------------------------------------------------------------------------

def store_holder(source_file: str) -> str:
    """The ``source_file`` the store's namespace holds a file's findings under."""
    from app.services.evidence_import import STORE_NAMESPACE

    return f"{STORE_NAMESPACE}:{source_file}"


def store_finding_id(holder: str, version_id: str, digest: str, ordinal: int) -> str:
    """The id of a store-namespace finding: its ``source_file``, the object's S3
    version id, the finding's canonical SHA-256 and its ordinal."""
    return str(uuid.uuid5(STORE_ID_NAMESPACE, f"store|{holder}|{version_id}|{digest}|{ordinal}"))


@dataclass(frozen=True)
class CheckedPentest:
    """What the store's import of one pentest version writes: ``rows`` (each
    the column values of one finding, None for a file without a ``findings``
    list) and their ``keys`` (``<digest>:<ordinal>``)."""

    key: str
    version_id: str
    source_file: str
    holder: str
    rows: tuple | None
    keys: tuple = ()

    @property
    def count(self) -> int:
        return len(self.keys)

    @property
    def identity(self) -> str:
        from app.services.evidence_import import identity_digest

        return identity_digest(self.keys)

    def info(self) -> dict:
        """The record's ``import_info`` for these findings: their count and identity."""
        return {"findings": self.count, "identity_sha256": self.identity}


def _utc_timestamp(value):
    """A scan timestamp as the import stores it, or :class:`ContentRejected`."""
    if not isinstance(value, datetime):
        return value
    try:
        return value if value.tzinfo is None else value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise ContentRejected("timestamp is outside the date-times the portal stores (UTC years 1 to 9999)") \
            from None


def _check_pentest(key: str, parsed, version_id: str) -> CheckedPentest:
    from app.models import PentestFinding
    from app.services.evidence_import import _check_lengths, coerce_record, unstorable_value
    from cli.loaders.base import SkipRecord
    from cli.loaders.pentest_findings import PentestFindingsLoader, finding_key

    if not isinstance(version_id, str) or not version_id:
        raise ContentRejected("the version has no version id")
    source_file, records = PentestFindingsLoader().build_file_records(key, parsed)
    holder = store_holder(source_file)
    if records is None:
        return CheckedPentest(key, version_id, source_file, holder, None)
    columns = PentestFinding.__table__.columns
    seen, rows, keys = collections.Counter(), [], []
    for index, record in enumerate(records):
        digest, ordinal = finding_key(record["other_data"], seen)
        record = dict(record, source_file=holder, id=store_finding_id(holder, version_id, digest, ordinal),
                      timestamp=_utc_timestamp(record.get("timestamp")))
        values = coerce_record(PentestFinding, record)
        try:
            _check_lengths(PentestFinding, values)
        except SkipRecord:
            continue  # a value longer than its column: skipped, as every pentest import skips it
        for name, value in values.items():
            refusal = unstorable_value(columns[name], value)
            if refusal:
                raise ContentRejected(f"finding {index}: {refusal}")
        rows.append(values)
        keys.append(f"{digest}:{ordinal}")
    return CheckedPentest(key, version_id, source_file, holder, tuple(rows), tuple(keys))


def check_pentest(key: str, parsed, version_id: str) -> CheckedPentest:
    """The pure, total content check of a parsed pentest file (module docstring):
    the findings the store's import inserts, or :class:`ContentRejected`."""
    return _total(_check_pentest, key, parsed, version_id)


@dataclass(frozen=True)
class Backing:
    """A store object that imported a path's findings into the store's namespace."""

    id: str
    bucket: str
    key: str
    version_id: str
    status: str
    count: int
    identity: str


def backing_records(source_files) -> dict:
    """``{source_file: [Backing]}``: for each ``layer<N>/<name>.json``, the records
    whose import stored its findings in the store's namespace (``ingested``, or
    erased since, with ``import_info.stored``), oldest first."""
    from app.models import db
    from app.models.evidence_store import EvidenceStoreObject

    wanted = sorted({name for name in source_files if isinstance(name, str)})
    found = collections.defaultdict(list)
    for start in range(0, len(wanted), _CHUNK):
        chunk = {PENTEST_PREFIX + name: name for name in wanted[start:start + _CHUNK]}
        rows = db.session.query(
            EvidenceStoreObject.id, EvidenceStoreObject.bucket, EvidenceStoreObject.key,
            EvidenceStoreObject.version_id, EvidenceStoreObject.status, EvidenceStoreObject.import_info,
            EvidenceStoreObject.created_at).filter(
            EvidenceStoreObject.kind == "pentest_evidence", EvidenceStoreObject.key_escaped.is_(False),
            EvidenceStoreObject.status.in_(("ingested", "erased")),
            EvidenceStoreObject.key.in_(sorted(chunk))).order_by(
            EvidenceStoreObject.created_at, EvidenceStoreObject.id).all()
        for row in rows:
            info = row.import_info if isinstance(row.import_info, dict) else {}
            if info.get("stored") is True and isinstance(info.get("findings"), int) \
                    and isinstance(info.get("identity_sha256"), str):
                found[chunk[row.key]].append(Backing(row.id, row.bucket, row.key, row.version_id, row.status,
                                                     info["findings"], info["identity_sha256"]))
    return found


@dataclass(frozen=True)
class PentestPlan:
    """What the store's import of a checked pentest file does with the database
    as it is now (:func:`plan_pentest`): ``outcome`` is ``import``,
    ``unchanged`` or ``duplicate`` (``duplicate_of`` holds exactly its
    findings); ``others`` are the other namespaces holding different findings
    for the path; ``note`` says why it is unchanged."""

    outcome: str
    duplicate_of: str | None = None
    others: tuple = ()
    note: str | None = None


def _describe(source_files) -> str:
    names = sorted(set(source_files))
    return ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")


def _held_ids(ids) -> dict:
    """``{id: source_file}`` of the stored findings holding any of ``ids``."""
    from app.models import PentestFinding, db

    ids = list(ids)
    held = {}
    for start in range(0, len(ids), _CHUNK):
        for row_id, source_file in db.session.query(PentestFinding.id, PentestFinding.source_file).filter(
                PentestFinding.id.in_(ids[start:start + _CHUNK])):
            held[row_id] = source_file
    return held


def plan_pentest(checked: CheckedPentest) -> PentestPlan:
    """Plan the store's import of a checked pentest file against the database
    (module docstring), writing nothing; :class:`Conflict` when the import
    would replace the store's findings or take over a stored row."""
    from app.services.evidence_import import pentest_holders

    if checked.rows is None:
        return PentestPlan(UNCHANGED, note="no findings list: nothing to import")
    holders = pentest_holders(checked.source_file)
    if not checked.count:
        return PentestPlan(UNCHANGED, others=tuple(sorted(holders)), note="no findings to import")
    backing = backing_records([checked.source_file]).get(checked.source_file)
    if backing:
        first = backing[0]
        if (first.count, first.identity) != (checked.count, checked.identity):
            raise Conflict(f"{CONFLICT}: the store's namespace already holds different findings for "
                           f"{checked.source_file} (another store object); the store never replaces its findings")
        return PentestPlan(UNCHANGED, others=tuple(sorted(holders)),
                           note="the store's namespace already holds exactly its findings")
    for holder, held in sorted(holders.items()):
        if held.matches(checked.count, checked.identity):
            return PentestPlan(DUPLICATE, holder, tuple(sorted(holders)))
    taken = _held_ids(row["id"] for row in checked.rows)
    if taken:
        raise Conflict(f"{CONFLICT}: {len(taken)} of the ids its findings take are already held by stored findings "
                       f"({_describe(taken.values())}); the store never takes over a finding")
    return PentestPlan(IMPORT, others=tuple(sorted(holders)))


def insert_store_findings(checked: CheckedPentest) -> int:
    """INSERT the checked findings into the store's namespace (flushes; the
    caller commits); returns how many."""
    from app.models import PentestFinding, db

    for values in checked.rows or ():
        db.session.add(PentestFinding(**values))
    db.session.flush()
    return checked.count


@dataclass(frozen=True)
class StoreHeld:
    """What the store's namespace holds for one path against its backing record:
    ``count`` / ``identity`` of the rows whose ids the record's version gives
    (recomputed from their content), ``consistent`` when their mapped columns
    match their content, and ``extra`` rows no backing record accounts for."""

    count: int
    identity: str
    consistent: bool
    extra: int


def store_holdings(versions: dict) -> dict:
    """``{holder: StoreHeld}`` for ``{holder: version id of its backing record}``
    (one query per 500 holders); a holder without rows is left out."""
    from app.services.evidence_import import finding_rows, identity_digest, mapped_columns_match
    from cli.loaders.pentest_findings import finding_digest

    result = {}
    for holder, rows in finding_rows(versions).items():
        version_id = versions[holder]
        by_digest = collections.defaultdict(list)
        for row in rows:
            by_digest[finding_digest(row.other_data)].append(row)
        keys, consistent, extra = [], True, 0
        for digest, group in by_digest.items():
            expected = {store_finding_id(holder, version_id, digest, ordinal): ordinal
                        for ordinal in range(len(group))}
            for row in group:
                ordinal = expected.get(row.id)
                if ordinal is None:
                    extra += 1
                    continue
                keys.append(f"{digest}:{ordinal}")
                consistent = consistent and mapped_columns_match(row, holder)
        result[holder] = StoreHeld(len(keys), identity_digest(keys), consistent, extra)
    return result


# ----------------------------------------------------------------------------
# Decision logs
# ----------------------------------------------------------------------------

@dataclass(frozen=True)
class CheckedDecisionLog:
    """A transcript the store's import may write: its session, its parsed
    entries and the (cleaned) agent and exit reason it names."""

    session_id: str
    parsed: object = field(repr=False)
    exit_reason: str | None
    agent: str | None


def _check_decision_log(content: bytes, key: str, exit_reason, agent) -> CheckedDecisionLog:
    from app.services import evidence_import_decision_logs as decision_logs
    from app.services.evidence_store import keys
    from app.services.transcript_ingest import TranscriptLimitError, parse_transcript

    session_id = keys.classify(key).session_id
    if not session_id or not decision_logs.SESSION_ID_RE.match(session_id):
        raise ContentRejected(f"invalid session id {str(session_id)[:80]!r}")
    if len(content) > decision_logs.MAX_TRANSCRIPT_BYTES:
        raise TooLarge(f"the transcript is {len(content)} bytes; the limit is "
                       f"{decision_logs.MAX_TRANSCRIPT_BYTES} bytes")
    try:
        parsed = parse_transcript(content)
    except TranscriptLimitError as exc:
        raise TooLarge(str(exc)) from None
    except ValueError as exc:
        raise ContentRejected(str(exc)) from None
    exit_reason = decision_logs.clean_metadata("exit_reason", exit_reason) if isinstance(exit_reason, str) else None
    return CheckedDecisionLog(session_id, parsed, exit_reason, agent if isinstance(agent, str) else None)


def check_decision_log(content: bytes, key: str, exit_reason=None, agent=None) -> CheckedDecisionLog:
    """The pure, total content check of a store transcript (module docstring):
    its parsed entries and cleaned metadata, or :class:`TooLarge` /
    :class:`ContentRejected`."""
    return _total(_check_decision_log, content, key, exit_reason, agent)


def plan_decision_log(checked: CheckedDecisionLog, content: bytes, key: str, record_id: str):
    """The decision-log import's outcome for a checked transcript with the store's
    authority, writing nothing (a ``DecisionLogResult``; status ``rejected`` is a
    conflict with the stored entries)."""
    from app.services import evidence_import_decision_logs as decision_logs

    return decision_logs.import_decision_log(
        content, session_id=checked.session_id, source_path=key, exit_reason=checked.exit_reason,
        agent_type=checked.agent, authority=decision_logs.AUTHORITY_STORE, store_object_id=record_id,
        dry_run=True, parsed=checked.parsed)
