"""Diff-only import of an evidence repository into the compliance tables.

An *evidence repository* is a directory (a git checkout, or files fetched
from a git host) with this layout::

    controls.json  systems.json  tests.json  policy-index.json  vendors.json
    risk-register.json  evidence/evidence-index.json
    pentest-evidence/layer<N>/*.json
    decision-logs/<timestamp>_<session-id>.jsonl   (+ optional <stem>.meta.json)

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
    Import a local checkout: datasets in :data:`DATASET_ORDER`, then decision
    logs. Commits after each file.
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
A namespaced import or removal of a path also takes over the findings that
``cli import`` stored for the same path (``source_file`` without a
namespace), so a database loaded by ``cli import`` and then synced from a
git source (the cutover) keeps no stale copies: those findings, stored
without a namespace and under the earlier id scheme, are deleted and the
file's findings created under the namespace - a one-time rebuild counted as
``retired`` (and reported by a git-source sync run as ``pentest_rebuild``).
Every deletion and creation is also an audit-log row. Other datasets are
keyed by their record ids and ignore ``namespace``.

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
    "DATASET_ORDER", "DEFAULT_EVIDENCE_MAPPINGS", "ImportCounts", "DecisionLogResult",
    "import_dataset_file", "remove_dataset_file", "import_decision_log", "import_directory",
    "classify_path", "session_id_from_path", "is_deadlock", "lock_session",
    "MAX_TRANSCRIPT_BYTES", "TranscriptTooLargeError",
    "AUTHORITY_SYSTEM", "AUTHORITY_ADMIN", "AUTHORITY_MEMBER",
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

# Repository path pattern → kind. ``*`` does not cross ``/``; ``**`` does.
# ``dataset:<name>`` kinds go to import_dataset_file(name, ...); ``decision_log``
# paths go to import_decision_log (a ``.manifest.json`` names a chunked file,
# see app.services.chunked_files).
DEFAULT_EVIDENCE_MAPPINGS = [
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

MAX_ERRORS = 100
_ID_CHUNK = 500
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


def import_directory(data_dir: str, *, dry_run: bool = False, include_decision_logs: bool = True,
                     datasets=None, log=None) -> dict:
    """Import a local evidence-repository checkout.

    Datasets are imported in :data:`DATASET_ORDER` (restricted to
    ``datasets`` when given), then decision logs from ``decision-logs/``: for
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
        selected = list(DATASET_ORDER)
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
