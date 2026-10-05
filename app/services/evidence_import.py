"""Diff-only import of an evidence repository into the compliance tables.

An *evidence repository* is a directory (a git checkout, or files fetched
from a git host) with this layout, which a git source reads by default
(:data:`DEFAULT_EVIDENCE_MAPPINGS`)::

    controls.json  systems.json  tests.json  policy-index.json  vendors.json
    risk-register.json  evidence/evidence-index.json
    pentest-evidence/layer<N>/*.json
    decision-logs/<timestamp>_<session-id>.jsonl   (+ optional <stem>.meta.json)

The six files from ``controls.json`` to ``risk-register.json`` are the
authored datasets (:data:`AUTHORED_EVIDENCE_MAPPINGS`,
:data:`DEFAULT_DATASETS`). ``cli import`` reads them by default, and the
evidence index, pentest evidence and decision logs when they are named
(``--dataset evidence``, ``--dataset pentest-findings``,
``--decision-logs``). The evidence store (``app.services.evidence_store``)
imports pentest evidence and decision logs alongside every git source; a
source whose repository leaves those kinds to the store has
:data:`AUTHORED_EVIDENCE_MAPPINGS` as its ``path_mappings``.

Every write to a compliance table produces an audit-log row, so the engine
writes **only real differences**: each record built from a file is compared
with the stored row and only the columns whose values differ are updated; a
file identical to what is stored issues no INSERT, UPDATE or DELETE at all.
Every call reports created / updated / unchanged / deleted / skipped counts.

Public API
----------
``import_dataset_file(dataset, path, data, namespace=None)``
    Import one dataset file (bytes, JSON text or parsed data). Flushes, does
    not commit. Used by the git-source sync for each changed file, with the
    source id as ``namespace``.
``remove_dataset_file(dataset, path, namespace=None)``
    A mapped file was deleted from the repository.
``import_decision_log(content, ...)``
    Store one decision-log transcript (see
    :mod:`app.services.evidence_import_decision_logs`). Flushes, does not commit.
``import_directory(data_dir)``
    Import a local checkout: the :data:`DEFAULT_DATASETS` (or the datasets
    named) in :data:`DATASET_ORDER`, then, when asked, decision logs.
    Commits after each file.
``classify_path(path)``
    The kind of a repository path per :data:`DEFAULT_EVIDENCE_MAPPINGS`.
``is_deadlock(exc)``
    True for a PostgreSQL deadlock (SQLSTATE 40P01); callers that write one
    file per transaction retry that transaction once.

Namespaces
----------
Pentest findings belong to the file that carries them. ``namespace`` (the
git source id for a git-source sync, ``None`` for ``cli import`` of a local
checkout) scopes that ownership: a finding's ``source_file`` is
``<namespace>:layer<N>/<file>.json`` (``layer<N>/<file>.json`` without a
namespace) and its id is derived from that ``source_file``, so two sources
with the same path never update, replace or delete each other's findings.
A namespaced import or removal of a path (every namespace but the evidence
store's) also takes over the findings that
``cli import`` stored for the same path (``source_file`` without a
namespace), so a database loaded by ``cli import`` and then synced from a
git source (the cutover) keeps no stale copies: those findings, stored
without a namespace and under the earlier id scheme, are deleted and the
file's findings created under the namespace - a one-time rebuild counted as
``retired`` (and reported by a git-source sync run as ``pentest_rebuild``).
Every deletion and creation is also an audit-log row. Other datasets are
keyed by their record ids and ignore ``namespace``.

The evidence store imports in its own namespace (:data:`STORE_NAMESPACE`)
through its own insert-only import (``app.services.evidence_store.plans``),
never through :func:`import_dataset_file` or :func:`remove_dataset_file`,
which refuse that namespace: it never takes over, updates or deletes the
findings of any other namespace, and no other import skips a file because
the store holds it. A set of findings is identified, in every namespace, by
its content (:func:`identity_digest` of each finding's canonical SHA-256 and
ordinal); :func:`pentest_holders` and :func:`held_findings` recompute what
each other namespace holds from its findings' content, and
:func:`unstorable_value` names a value the database refuses.

Diff semantics
--------------
* Values are compared after normalisation: datetimes as UTC instants (a
  naive value is UTC), JSON columns by canonical JSON (sorted keys), other
  values as the column's Python type (a JSON number bound for a text column
  compares as its text). ``updated_at`` is bookkeeping and never counts as a
  difference; when a row does change, a file-supplied ``updated_at`` is
  written with it, otherwise the model stamps the time of the change.
* A column the file does not mention keeps its stored value. ``other_data``
  is always mentioned: it holds exactly the file's unmapped fields, so a field
  removed from the file disappears from ``other_data``.
* Datetimes written to ``timestamp without time zone`` columns are stored as
  naive UTC, so the stored value never depends on the database session's
  time zone.
* Many-to-many links (policy → controls via ``soc2_control_ids``, vendor →
  systems via ``system_ids``) are written only when the set of resolvable ids
  differs from the stored links. An empty or missing list leaves the links as
  they are. Unresolvable ids are reported as errors and skipped.
* Records are never deleted because they disappeared from a dataset file or
  because a dataset file was removed. The exception is pentest evidence: each
  ``pentest-evidence/layer<N>/*.json`` file is authoritative for the findings
  whose ``source_file`` is that file, so findings no longer in the file (and
  rows stored under earlier id formulas) are deleted, and removing the file
  deletes its findings. Files without a ``findings`` list are skipped.
* A record that cannot be imported (missing id, unresolvable required
  reference, missing required field, value longer than its column, a URL
  column - ``app.security.URL_FIELDS``: evidence ``url``, the vendor URL
  columns - holding anything but an absolute http(s) URL, duplicate id within
  a file) is skipped with an error line; the rest of the file is imported.
  When the same id occurs twice in a file the last occurrence wins.
* Dry run issues no writes: every file is compared with the current database.
  Ids the same run would create count as existing for later reference checks,
  but evidence rows that resolve their test by name can only resolve against
  tests already stored.
"""

import collections
import functools
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import sqlalchemy as sa

from app.models import db
from app.services.evidence_import_decision_logs import (  # noqa: F401 (re-exported API)
    AUTHORITY_ADMIN,
    AUTHORITY_MEMBER,
    AUTHORITY_STORE,
    AUTHORITY_SYSTEM,
    MAX_TRANSCRIPT_BYTES,
    DecisionLogResult,
    TranscriptTooLargeError,
    describe_exception,
    import_decision_log,
    import_decision_log_directory,
    lock_session,
    session_id_from_path,
)

logger = logging.getLogger(__name__)

__all__ = [
    "AUTHORED_EVIDENCE_MAPPINGS", "DATASET_ORDER", "DEFAULT_DATASETS", "DEFAULT_EVIDENCE_MAPPINGS",
    "ImportCounts", "DecisionLogResult",
    "import_dataset_file", "remove_dataset_file", "import_decision_log", "import_directory",
    "classify_path", "session_id_from_path", "is_deadlock", "lock_session",
    "MAX_TRANSCRIPT_BYTES", "TranscriptTooLargeError",
    "AUTHORITY_SYSTEM", "AUTHORITY_STORE", "AUTHORITY_ADMIN", "AUTHORITY_MEMBER", "STORE_NAMESPACE",
]

DEADLOCK_SQLSTATE = "40P01"


def is_deadlock(exc) -> bool:
    """True when ``exc`` (a SQLAlchemy error or a DB-API error) is a PostgreSQL deadlock."""
    original = getattr(exc, "orig", exc)
    return getattr(original, "pgcode", None) == DEADLOCK_SQLSTATE


DATASET_ORDER = [
    "controls", "systems", "tests", "policies", "vendors", "evidence",
    "risk-register", "pentest-findings",
]

# The authored datasets: what ``cli import`` reads by default (in DATASET_ORDER).
DEFAULT_DATASETS = ["controls", "systems", "tests", "policies", "vendors", "risk-register"]

# Repository path pattern → kind. ``*`` does not cross ``/``; ``**`` does.
# ``dataset:<name>`` kinds go to import_dataset_file(name, ...); ``decision_log``
# paths go to import_decision_log (a ``.manifest.json`` names a chunked file,
# see app.services.chunked_files).
# The authored datasets' mappings: the ``path_mappings`` of a source whose
# repository leaves pentest evidence and decision logs to the evidence store.
AUTHORED_EVIDENCE_MAPPINGS = [
    {"pattern": "controls.json", "kind": "dataset:controls"},
    {"pattern": "systems.json", "kind": "dataset:systems"},
    {"pattern": "tests.json", "kind": "dataset:tests"},
    {"pattern": "policy-index.json", "kind": "dataset:policies"},
    {"pattern": "vendors.json", "kind": "dataset:vendors"},
    {"pattern": "risk-register.json", "kind": "dataset:risk-register"},
]
# A git source's defaults: every kind of the evidence repository layout.
DEFAULT_EVIDENCE_MAPPINGS = AUTHORED_EVIDENCE_MAPPINGS + [
    {"pattern": "evidence/evidence-index.json", "kind": "dataset:evidence"},
    {"pattern": "pentest-evidence/layer*/*.json", "kind": "dataset:pentest-findings"},
    {"pattern": "decision-logs/*.jsonl", "kind": "decision_log"},
    {"pattern": "decision-logs/*.jsonl.manifest.json", "kind": "decision_log"},
]

MAX_ERRORS = 100
_ID_CHUNK = 500
# Pentest-findings namespace of the evidence store (app.services.evidence_store).
STORE_NAMESPACE = "evidence-store"
_BOOKKEEPING_COLUMNS = ("updated_at",)


@dataclass
class ImportCounts:
    """Outcome counts of an import. ``errors`` holds at most 100 lines."""

    created: int = 0
    updated: int = 0
    unchanged: int = 0
    deleted: int = 0
    skipped: int = 0
    retired: int = 0  # of ``deleted``: pentest findings taken over from a stored-without-namespace copy
    errors: list = field(default_factory=list)
    errors_omitted: int = 0

    def error(self, message: str) -> None:
        """Record a human-readable error line (beyond the cap only counted)."""
        if len(self.errors) < MAX_ERRORS:
            self.errors.append(message)
        else:
            self.errors_omitted += 1

    def add(self, other: "ImportCounts") -> None:
        """Add ``other``'s counts and errors to this one."""
        self.created += other.created
        self.updated += other.updated
        self.unchanged += other.unchanged
        self.deleted += other.deleted
        self.skipped += other.skipped
        self.retired += other.retired
        for message in other.errors:
            self.error(message)
        self.errors_omitted += other.errors_omitted

    def as_dict(self) -> dict:
        return {
            "created": self.created,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "deleted": self.deleted,
            "skipped": self.skipped,
            "retired": self.retired,
            "errors": list(self.errors),
            "errors_omitted": self.errors_omitted,
        }


class ImportContext:
    """State shared by the files of one import run.

    Caches the id sets used for reference checks and remembers ids the run
    creates (so a dry run can resolve references to records it would create).
    ``bulk`` marks a whole-directory run, which preloads the pentest index.
    ``namespace`` scopes pentest findings (see "Namespaces" above).
    """

    def __init__(self, dry_run=False, bulk=False, namespace=None):
        self.dry_run = dry_run
        self.bulk = bulk
        self.namespace = namespace
        self.cache = {}
        self.failed_files = []
        self._ids = {}
        self._planned = {}

    def ids(self, model):
        """Set of ids of ``model`` stored (or created earlier in this run)."""
        known = self._ids.get(model)
        if known is None:
            known = {row[0] for row in db.session.query(model.id)}
            known |= self._planned.get(model, set())
            self._ids[model] = known
        return known

    def note_created(self, model, record_id):
        self._planned.setdefault(model, set()).add(record_id)
        if model in self._ids:
            self._ids[model].add(record_id)

    def after_rollback(self):
        """Forget cached state that a rolled-back file may have added."""
        self._ids.clear()
        if not self.dry_run:
            self._planned.clear()


# --------------------------------------------------------------------------
# Paths and classification
# --------------------------------------------------------------------------

@functools.lru_cache(maxsize=256)
def _glob_regex(pattern):
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif ch == "*":
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch == "[" and pattern.find("]", i + 2) != -1:
            end = pattern.find("]", i + 2)
            body = pattern[i + 1:end]
            if body.startswith("!"):
                body = "^" + body[1:]
            out.append("[" + body.replace("\\", "\\\\") + "]")
            i = end + 1
        else:
            out.append(re.escape(ch))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def _normalize_repo_path(path):
    norm = str(path).replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    return norm.lstrip("/")


def classify_path(path: str, mappings=None):
    """Kind of a repository-relative path, or None when no mapping matches.

    ``mappings`` is a list of ``{"pattern", "kind"}`` dicts or
    ``(pattern, kind)`` pairs (default :data:`DEFAULT_EVIDENCE_MAPPINGS`);
    the first match wins. ``*`` and ``?`` do not match ``/``; ``**`` does.
    """
    norm = _normalize_repo_path(path)
    for mapping in DEFAULT_EVIDENCE_MAPPINGS if mappings is None else mappings:
        if isinstance(mapping, dict):
            pattern, kind = mapping["pattern"], mapping["kind"]
        else:
            pattern, kind = mapping
        if _glob_regex(_normalize_repo_path(pattern)).match(norm):
            return kind
    return None


# --------------------------------------------------------------------------
# Value normalisation and comparison
# --------------------------------------------------------------------------

def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _as_utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def coerce_value(column, value):
    """The value as it will be stored in ``column`` (and compared)."""
    if value is None:
        return None
    col_type = column.type
    if isinstance(col_type, sa.JSON):
        return value
    if isinstance(col_type, sa.DateTime):
        if isinstance(value, datetime):
            if col_type.timezone:
                return _as_utc(value)
            return _as_utc(value).replace(tzinfo=None)
        return value
    if isinstance(col_type, sa.String):
        if isinstance(value, str):
            return value
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True)
        return value
    if isinstance(col_type, sa.Boolean):
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        return value
    if isinstance(col_type, sa.Integer):
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, float) and value.is_integer():
            return int(value)
        if isinstance(value, str):
            try:
                return int(value.strip())
            except ValueError:
                return value
        return value
    if isinstance(col_type, sa.Float):
        if isinstance(value, bool):
            return float(value)
        if isinstance(value, (int, str)):
            try:
                return float(value)
            except ValueError:
                return value
    return value


def values_equal(column, stored, new):
    """True when the stored value and the new (coerced) value are the same."""
    if stored is None or new is None:
        return stored is None and new is None
    col_type = column.type
    if isinstance(col_type, sa.JSON):
        return _canonical_json(stored) == _canonical_json(new)
    if isinstance(stored, datetime) and isinstance(new, datetime):
        return _as_utc(stored) == _as_utc(new)
    return stored == new


def coerce_record(model, record):
    """Record restricted to the model's columns, with values coerced for storage."""
    columns = model.__table__.columns
    return {key: coerce_value(columns[key], value) for key, value in record.items() if key in columns}


@functools.lru_cache(maxsize=64)
def _required_columns(model):
    return tuple(
        col.key for col in model.__table__.columns
        if not col.nullable and not col.primary_key
        and col.default is None and col.server_default is None
    )


def _check_lengths(model, values):
    from cli.loaders.base import SkipRecord

    columns = model.__table__.columns
    for key, value in values.items():
        length = getattr(columns[key].type, "length", None)
        if length and isinstance(value, str) and len(value) > length:
            raise SkipRecord(f"{key} is longer than {length} characters")


def _check_urls(model, values):
    """URL columns hold absolute http(s) URLs only, as the API and admin UI require."""
    from app.security import url_fields_error
    from cli.loaders.base import SkipRecord

    message = url_fields_error(model.__tablename__, values)
    if message:
        raise SkipRecord(message)


def _diff(obj, values, columns):
    changes = {}
    for key, new in values.items():
        if key == "id" or key in _BOOKKEEPING_COLUMNS:
            continue
        if not values_equal(columns[key], getattr(obj, key), new):
            changes[key] = new
    if changes:
        for key in _BOOKKEEPING_COLUMNS:
            if values.get(key) is not None:
                changes[key] = values[key]
    return changes


# --------------------------------------------------------------------------
# Record synchronisation
# --------------------------------------------------------------------------

def _load_existing(model, ids):
    existing = {}
    ids = list(ids)
    for start in range(0, len(ids), _ID_CHUNK):
        chunk = ids[start:start + _ID_CHUNK]
        for obj in db.session.query(model).filter(model.id.in_(chunk)):
            existing[obj.id] = obj
    return existing


def _sync_links(loader, obj, values, counts, ctx, label):
    """Bring a many-to-many link set in line with the file; True when it differs."""
    spec = loader.link
    if spec is None:
        return False
    wanted_raw = (values.get("other_data") or {}).get(spec.key)
    if not wanted_raw:
        return False
    if not isinstance(wanted_raw, list):
        counts.error(f"{label}: {spec.key} is not a list; links left unchanged")
        return False
    known = ctx.ids(spec.target)
    wanted = []
    for target_id in wanted_raw:
        if not isinstance(target_id, str) or target_id not in known:
            counts.error(f"{label}: {spec.key} entry {target_id!r} not found; link skipped")
        elif target_id not in wanted:
            wanted.append(target_id)
    current = set()
    if obj is not None and sa.inspect(obj).persistent:
        current = {target.id for target in getattr(obj, spec.relationship)}
    if set(wanted) == current:
        return False
    if not ctx.dry_run and obj is not None:
        targets = [db.session.get(spec.target, target_id) for target_id in wanted]
        setattr(obj, spec.relationship, [target for target in targets if target is not None])
    return True


def _sync_records(loader, entries, counts, ctx, existing=None):
    """Create or update each ``(label, values)`` entry, writing only differences."""
    model = loader.model_class
    columns = model.__table__.columns
    required = _required_columns(model)
    if existing is None:
        existing = _load_existing(model, [values["id"] for _, values in entries])

    for label, values in entries:
        obj = existing.get(values["id"])
        if obj is None:
            missing = [key for key in required if values.get(key) is None]
            if missing:
                counts.skipped += 1
                counts.error(f"{label}: missing required field(s): {', '.join(missing)}")
                continue
            counts.created += 1
            ctx.note_created(model, values["id"])
            new_obj = None
            if not ctx.dry_run:
                new_obj = model(**values)
                db.session.add(new_obj)
            _sync_links(loader, new_obj, values, counts, ctx, label)
            continue

        nulls = [key for key in required if key in values and values[key] is None]
        if nulls:
            counts.skipped += 1
            counts.error(f"{label}: required field(s) set to null: {', '.join(nulls)}")
            continue
        changes = _diff(obj, values, columns)
        links_changed = _sync_links(loader, obj, values, counts, ctx, label)
        if changes or links_changed:
            counts.updated += 1
            if not ctx.dry_run:
                for key, value in changes.items():
                    setattr(obj, key, value)
        else:
            counts.unchanged += 1


def _import_list_dataset(loader, path, parsed, counts, ctx):
    from cli.loaders.base import SkipRecord

    if not isinstance(parsed, list):
        counts.skipped += 1
        counts.error(f"{path}: expected a JSON array, got {type(parsed).__name__}")
        return
    model = loader.model_class
    entries = []
    position = {}
    for index, item in enumerate(parsed):
        label = f"{path}: item {index}"
        if not isinstance(item, dict):
            counts.skipped += 1
            counts.error(f"{label}: expected a JSON object")
            continue
        try:
            record = loader._build_record(item)
            if record is None:
                raise SkipRecord("could not be built")
            if record.get("id") in (None, ""):
                raise SkipRecord("id is missing")
            label = f"{label} (id={record['id']})"
            warnings = loader.resolve_references(item, record, ctx)
            values = coerce_record(model, record)
            _check_lengths(model, values)
            _check_urls(model, values)
        except SkipRecord as exc:
            counts.skipped += 1
            counts.error(f"{label}: {exc}")
            continue
        for warning in warnings or ():
            counts.error(f"{label}: {warning}")
        record_id = values["id"]
        if record_id in position:
            counts.skipped += 1
            counts.error(f"{label}: duplicate id in file; the last occurrence is imported")
            entries[position[record_id]] = (label, values)
        else:
            position[record_id] = len(entries)
            entries.append((label, values))
    _sync_records(loader, entries, counts, ctx)


def _namespaced(source_file, namespace):
    return source_file if namespace is None else f"{namespace}:{source_file}"


def _owned_source_files(source_file, namespace):
    """The ``source_file`` values whose findings a file owns (see "Namespaces")."""
    if namespace is None:
        return (source_file,)
    return (_namespaced(source_file, namespace), source_file)


def _apply_namespace(records, namespace):
    """Move a file's records into ``namespace``: namespaced source_file and ids."""
    from cli.loaders.pentest_findings import finding_id

    if namespace is None or not records:
        return
    source_file = _namespaced(records[0]["source_file"], namespace)
    seen = collections.Counter()
    for record in records:
        record["source_file"] = source_file
        record["id"] = finding_id(source_file, record["other_data"], seen)


def identity_digest(keys) -> str:
    """SHA-256 of a file's finding keys (``<digest>:<ordinal>``: each finding's
    canonical SHA-256 and its ordinal among identical findings), sorted and
    comma-joined: the identity of a set of findings, the same in every
    namespace that holds them."""
    import hashlib

    return hashlib.sha256(",".join(sorted(keys)).encode("utf-8")).hexdigest()


def finding_keys(findings) -> list:
    """The keys (:func:`identity_digest`) of ``findings`` (each a finding's
    ``other_data``), in order."""
    from cli.loaders.pentest_findings import finding_key

    seen = collections.Counter()
    return ["%s:%d" % finding_key(finding, seen) for finding in findings]


@dataclass(frozen=True)
class HeldFindings:
    """The findings one ``source_file`` holds, recomputed from their content.

    ``count`` rows; ``identity`` is :func:`identity_digest` of their content's
    keys; ``consistent`` is True when every row's id is the one its content
    gives under that ``source_file`` and its mapped columns (severity,
    summary, remediation, SOC 2 controls, file path, layer) are the ones its
    content maps to - an edited or re-keyed finding makes it False.
    """

    count: int
    identity: str
    consistent: bool

    def matches(self, count: int, identity: str) -> bool:
        """True when these findings are exactly the ``count`` findings of ``identity``."""
        return self.consistent and (self.count, self.identity) == (count, identity)


_MAPPED_FINDING_COLUMNS = ("severity", "summary", "remediation", "soc2_controls", "file_path", "layer")


def holder_layer(holder: str):
    """The layer number of a stored ``source_file`` (``[<namespace>:]layer<N>/<file>.json``), or None."""
    match = re.fullmatch(r"layer(\d+)", holder.rsplit("/", 1)[0].rsplit(":", 1)[-1])
    return int(match.group(1)) if match else None


def mapped_columns_match(row, holder: str) -> bool:
    """True when a stored finding's mapped columns are the ones its content
    (``other_data``) maps to under ``holder``; False for an edited finding or
    one whose content is not a JSON object."""
    from app.models import PentestFinding
    from cli.loaders.pentest_findings import PentestFindingsLoader

    finding = row.other_data
    if not isinstance(finding, dict):
        return False
    columns = PentestFinding.__table__.columns
    expected = coerce_record(PentestFinding, PentestFindingsLoader._finding_record(
        None, finding, "", holder_layer(holder), "", holder, None))
    return all(values_equal(columns[name], coerce_value(columns[name], getattr(row, name)), expected[name])
               for name in _MAPPED_FINDING_COLUMNS)


def finding_rows(source_files) -> dict:
    """``{source_file: [row]}`` of the stored findings of ``source_files`` (one query
    per 500 names; each row with its id, ``other_data`` and mapped columns)."""
    from app.models import PentestFinding

    wanted = sorted({name for name in source_files if isinstance(name, str)})
    model = PentestFinding
    rows = collections.defaultdict(list)
    for start in range(0, len(wanted), _ID_CHUNK):
        for row in db.session.query(model.source_file, model.id, model.other_data,
                                    *[getattr(model, name) for name in _MAPPED_FINDING_COLUMNS]).filter(
                model.source_file.in_(wanted[start:start + _ID_CHUNK])):
            rows[row.source_file].append(row)
    return rows


def held_findings(source_files) -> dict:
    """``{source_file: HeldFindings}`` of every one of ``source_files`` holding findings,
    each row's content re-hashed and its id recomputed under that ``source_file``
    (``v2`` ids: every namespace but the evidence store's, whose findings
    ``app.services.evidence_store.plans.store_holdings`` recomputes)."""
    from cli.loaders.pentest_findings import finding_id

    held = {}
    for holder, found in finding_rows(source_files).items():
        seen, recomputed, consistent = collections.Counter(), [], True
        for row in found:
            consistent = consistent and mapped_columns_match(row, holder)
            recomputed.append(finding_id(holder, row.other_data, seen))
        consistent = consistent and sorted(row.id for row in found) == sorted(recomputed)
        held[holder] = HeldFindings(len(found), identity_digest(finding_keys(row.other_data for row in found)),
                                    consistent)
    return held


def pentest_holders(source_file):
    """``{stored source_file: HeldFindings}`` of every namespace but the evidence
    store's holding findings of ``layer<N>/<file>.json`` (``cli import`` under the
    bare path, each other namespace under ``<namespace>:<path>``), each recomputed
    from its findings' content (:func:`held_findings`)."""
    from app.models import PentestFinding

    names = {row[0] for row in db.session.query(PentestFinding.source_file).filter(
        sa.or_(PentestFinding.source_file == source_file,
               PentestFinding.source_file.endswith(":" + source_file, autoescape=True))).distinct()}
    return held_findings(names - {_namespaced(source_file, STORE_NAMESPACE)})


def _text_problem(value: str) -> str | None:
    if "\x00" in value:
        return "a NUL character"
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return "an unpaired surrogate (text that is not UTF-8)"
    return None


def _json_problem(value) -> str | None:
    """Why a JSON value cannot be stored (and audited as JSONB), or None."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, bool) or item is None or isinstance(item, int):
            continue
        if isinstance(item, float):
            if item != item or item in (float("inf"), float("-inf")):
                return "a non-finite number (NaN or Infinity), which JSON cannot hold"
        elif isinstance(item, str):
            problem = _text_problem(item)
            if problem:
                return problem
        elif isinstance(item, dict):
            for name, member in item.items():
                if not isinstance(name, str):
                    return "a member name that is not text"
                problem = _text_problem(name)
                if problem:
                    return problem + " in a member name"
                stack.append(member)
        elif isinstance(item, list):
            stack.extend(item)
        else:
            return f"a {type(item).__name__}, which JSON cannot hold"
    return None


def unstorable_value(column, value) -> str | None:
    """Why the database (or the audit log, which records each row as JSONB)
    refuses ``value`` for ``column``, or None when it stores it: text holding a
    NUL character or an unpaired surrogate (in a text column, or anywhere in a
    JSON value, member names included), a non-finite number in JSON, a value
    of a type the column does not take, a date-time outside the years 1 to
    9999."""
    if value is None:
        return None
    column_type = column.type
    if isinstance(column_type, sa.JSON):
        problem = _json_problem(value)
    elif isinstance(column_type, sa.String):
        problem = _text_problem(value) if isinstance(value, str) else "a value that is not text"
    elif isinstance(column_type, sa.DateTime):
        problem = None if isinstance(value, datetime) else "a value that is not a date-time"
    elif isinstance(column_type, sa.Integer):
        problem = None if isinstance(value, int) and not isinstance(value, bool) and -2**31 <= value < 2**31 \
            else "a value that is not a 32-bit integer"
    else:
        problem = None
    return f"{column.key} holds {problem}, which the database cannot store" if problem else None


def _existing_pentest_rows(model, source_files, ids, ctx):
    """Stored findings of ``source_files`` plus any stored rows with the new ids."""
    if ctx.bulk:
        index = ctx.cache.get("pentest_ids_by_source_file")
        if index is None:
            index = {}
            for row_id, row_source in db.session.query(model.id, model.source_file):
                index.setdefault(row_source, set()).add(row_id)
            ctx.cache["pentest_ids_by_source_file"] = index
        owned = set().union(*(index.get(name, set()) for name in source_files))
        return _load_existing(model, set(ids) | owned)
    existing = {
        obj.id: obj
        for obj in db.session.query(model).filter(model.source_file.in_(source_files))
    }
    existing.update(_load_existing(model, [i for i in ids if i not in existing]))
    return existing


def _import_pentest_file(loader, path, parsed, counts, ctx):
    from cli.loaders.base import SkipRecord

    try:
        source_file, records = loader.build_file_records(path, parsed)
    except SkipRecord as exc:
        counts.skipped += 1
        counts.error(str(exc))
        return
    if records is None:
        counts.skipped += 1  # no findings list (e.g. a *-summary.json file)
        return
    _apply_namespace(records, ctx.namespace)
    owned = _owned_source_files(source_file, ctx.namespace)

    model = loader.model_class
    entries = []
    file_ids = set()
    for index, record in enumerate(records):
        file_ids.add(record["id"])
        label = f"{path}: finding {index}"
        values = coerce_record(model, record)
        try:
            _check_lengths(model, values)
        except SkipRecord as exc:
            counts.skipped += 1
            counts.error(f"{label}: {exc}")
            continue
        entries.append((label, values))

    existing = _existing_pentest_rows(model, owned, file_ids, ctx)
    _sync_records(loader, entries, counts, ctx, existing=existing)

    stale = [
        obj for obj_id, obj in existing.items()
        if obj_id not in file_ids and obj.source_file in owned
    ]
    counts.deleted += len(stale)
    counts.retired += sum(1 for obj in stale if obj.source_file != _namespaced(source_file, ctx.namespace))
    if not ctx.dry_run:
        for obj in stale:
            db.session.delete(obj)


def _parse_json(path, data):
    if isinstance(data, (bytes, bytearray)):
        try:
            data = bytes(data).decode("utf-8-sig")
        except UnicodeDecodeError:
            raise ValueError(f"{path}: not UTF-8 text") from None
    if isinstance(data, str):
        try:
            return json.loads(data)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})") from None
    if isinstance(data, (list, dict)):
        return data
    raise ValueError(f"{path}: unsupported data type {type(data).__name__}")


def _loader_for(dataset):
    from cli.loaders import LOADERS_BY_DATASET

    loader_class = LOADERS_BY_DATASET.get(dataset)
    if loader_class is None:
        raise ValueError(f"unknown dataset {dataset!r}; expected one of {', '.join(DATASET_ORDER)}")
    return loader_class()


def _import_parsed(loader, path, parsed, ctx):
    counts = ImportCounts()
    if hasattr(loader, "build_file_records"):
        _import_pentest_file(loader, path, parsed, counts, ctx)
    else:
        _import_list_dataset(loader, path, parsed, counts, ctx)
    if not ctx.dry_run:
        db.session.flush()
    return counts


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def import_dataset_file(dataset: str, path: str, data, *, dry_run: bool = False,
                        namespace: str | None = None) -> ImportCounts:
    """Import one dataset file, writing only real differences.

    ``data`` is the file's bytes, its JSON text, or already-parsed JSON;
    ``path`` is its repository-relative path (for pentest evidence it
    determines ``source_file``, within ``namespace``; see "Namespaces").
    Flushes but does not commit. Raises ValueError for an unknown dataset or
    unparseable JSON.
    """
    if namespace == STORE_NAMESPACE:
        raise ValueError("the evidence store's namespace is written only by the evidence store's sync")
    loader = _loader_for(dataset)
    parsed = _parse_json(path, data)
    return _import_parsed(loader, path, parsed, ImportContext(dry_run=dry_run, namespace=namespace))


def remove_dataset_file(dataset: str, path: str, *, dry_run: bool = False,
                        namespace: str | None = None) -> ImportCounts:
    """Handle the removal of a mapped dataset file from the repository.

    Pentest evidence: the findings the file owns within ``namespace`` are
    deleted (see "Namespaces"). Other datasets: their records are kept
    (``skipped=1`` with an explanatory error line). Flushes but does not
    commit.
    """
    from cli.loaders.base import SkipRecord

    if namespace == STORE_NAMESPACE:
        raise ValueError("the evidence store's findings are never removed")
    loader = _loader_for(dataset)
    counts = ImportCounts()
    if not hasattr(loader, "build_file_records"):
        counts.skipped = 1
        counts.error(
            f"{path}: removed from the repository; {dataset} records are kept "
            "(records are never deleted because a dataset file was removed)")
        return counts
    try:
        source_file, _ = loader.source_file_for(path)
    except SkipRecord as exc:
        counts.skipped = 1
        counts.error(str(exc))
        return counts
    model = loader.model_class
    owned = _owned_source_files(source_file, namespace)
    rows = db.session.query(model).filter(model.source_file.in_(owned)).all()
    counts.deleted = len(rows)
    if not dry_run and rows:
        for row in rows:
            db.session.delete(row)
        db.session.flush()
    return counts


def import_loader_from_directory(loader, data_dir, *, dry_run=False, ctx=None, log=None) -> ImportCounts:
    """Import every file of one loader found in ``data_dir``, committing after each.

    A file that cannot be read, parsed or written is rolled back on its own,
    counted as skipped and reported; the other files are still imported.
    """
    log = log or logger.info
    ctx = ctx or ImportContext(dry_run=dry_run, bulk=True)
    counts = ImportCounts()
    name = loader.dataset or loader.file_name
    if loader.model_class is None:
        counts.error(f"{name}: the loader has no model; nothing imported")
        return counts
    if hasattr(loader, "iter_paths"):
        paths = loader.iter_paths(data_dir)
    elif os.path.isfile(os.path.join(data_dir, loader.file_name)):
        paths = [loader.file_name]
    else:
        paths = []
    if not paths:
        log(f"{name}: {loader.file_name} not found; nothing to import")
        return counts

    for path in paths:
        try:
            with open(os.path.join(data_dir, path), "rb") as fh:
                raw = fh.read()
            file_counts = _import_parsed(loader, path, _parse_json(path, raw), ctx)
            if not dry_run:
                db.session.commit()
        except Exception as exc:  # one bad file must not stop the import
            db.session.rollback()
            ctx.after_rollback()
            ctx.failed_files.append(path)
            logger.warning("Import of %s failed", path, exc_info=not isinstance(exc, ValueError))
            counts.skipped += 1
            counts.error(f"{path}: not imported ({describe_exception(exc)})")
            continue
        counts.add(file_counts)
    return counts


def import_directory(data_dir: str, *, dry_run: bool = False, include_decision_logs: bool = False,
                     datasets=None, log=None) -> dict:
    """Import a local evidence-repository checkout.

    Datasets are imported in :data:`DATASET_ORDER`: the
    :data:`DEFAULT_DATASETS`, or exactly ``datasets`` when given (``evidence``
    and ``pentest-findings`` are imported only when named). With
    ``include_decision_logs``, decision logs follow from ``decision-logs/``: for
    each session the largest export wins, chunked transcripts are
    reassembled, and a ``<stem>.meta.json`` sidecar supplies the exit reason
    and the agent label of a new session. Commits after each file. A rejected transcript (one that does not extend
    the stored one) counts as a failed file. Returns::

        {"datasets": {name: counts_dict}, "decision_logs": {"created", "replaced",
         "unchanged", "kept_existing", "rejected", "failed"}, "totals": {...},
         "errors": [...], "errors_omitted": n, "failed_files": n}
    """
    log = log or logger.info
    if not os.path.isdir(data_dir):
        raise ValueError(f"data directory does not exist: {data_dir}")
    if datasets is None:
        selected = [name for name in DATASET_ORDER if name in DEFAULT_DATASETS]
    else:
        unknown = [name for name in datasets if name not in DATASET_ORDER]
        if unknown:
            raise ValueError(f"unknown dataset(s): {', '.join(unknown)}")
        selected = [name for name in DATASET_ORDER if name in datasets]

    ctx = ImportContext(dry_run=dry_run, bulk=True)
    all_counts = ImportCounts()
    result = {"datasets": {}}
    for name in selected:
        started = time.monotonic()
        counts = import_loader_from_directory(_loader_for(name), data_dir, dry_run=dry_run, ctx=ctx, log=log)
        result["datasets"][name] = counts.as_dict()
        all_counts.add(counts)
        log(f"{name}: created={counts.created} updated={counts.updated} "
            f"unchanged={counts.unchanged} deleted={counts.deleted} "
            f"skipped={counts.skipped} ({time.monotonic() - started:.1f}s)")

    decision_logs = {"created": 0, "replaced": 0, "unchanged": 0, "kept_existing": 0, "rejected": 0,
                     "failed": 0}
    decision_log_dir = os.path.join(data_dir, "decision-logs")
    if include_decision_logs and os.path.isdir(decision_log_dir):
        started = time.monotonic()
        decision_logs, errors = import_decision_log_directory(
            decision_log_dir, dry_run=dry_run, path_prefix="decision-logs")
        for message in errors:
            all_counts.error(message)
        log("decision-logs: " + " ".join(f"{k}={v}" for k, v in decision_logs.items())
            + f" ({time.monotonic() - started:.1f}s)")
    result["decision_logs"] = decision_logs

    totals = all_counts.as_dict()
    result["errors"] = totals.pop("errors")
    result["errors_omitted"] = totals.pop("errors_omitted")
    result["totals"] = totals
    result["failed_files"] = (len(ctx.failed_files) + decision_logs.get("failed", 0)
                              + decision_logs.get("rejected", 0))
    return result
