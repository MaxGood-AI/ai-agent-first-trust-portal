"""Verify the evidence store against the portal's records
(``python -m cli audit-verify --evidence-store [--full]``,
``GET /api/evidence-store/verify``) and decision-log versions against their
store objects (``audit-verify --decision-logs --against-store``).

The records are audited (``evidence_store_objects``), so the witnessed audit
chain fixes what the portal recorded; the store is write-once, so a version
that still matches its record is the version the portal imported.

Store verification (:func:`verify_store`)
-----------------------------------------
- **Bucket** (the configured one, :func:`check_bucket`): versioning is
  ``Enabled``; Object Lock is enabled with a default retention in
  ``GOVERNANCE`` or ``COMPLIANCE`` mode whose period is no lower than the
  bucket's retention FLOOR (``evidence_store_retention_floors``: set from the
  default at the bucket's first sync, lowered only by ``python -m cli
  evidence-store set-retention-floor``; a bucket with records and no floor
  fails); the bucket policy denies to every principal the protected actions
  on every store prefix and a ``PutObject`` without ``If-None-Match``
  (:func:`check_policy`, resources in the partition of the region the
  portal runs in); no lifecycle rule expires or transitions versions
  (:func:`check_lifecycle`; ``AbortIncompleteMultipartUpload`` is allowed).
  The bucket's floors are appended, never changed (each change is a new
  row; the latest is the floor): its first floor must be the default
  retention its first sync observed (:func:`retention_floor_history`; runs
  and records are dated by the database clock) and no lower than the Object
  Lock retention from its upload of the earliest version the portal
  recorded in the bucket (:func:`first_floor_issues`), and every lowering
  is listed (``retention_floor_lowerings``, informational and attributed by
  the witnessed audit log). Anything else is a failure. While
  the policy's documented erasure exception names a principal, the
  verification is ``unverified`` and names it.
- **Records** (every record, of any bucket, each against its own recorded
  bucket; keyset-paginated by id, checked with ``HeadObject`` by
  :data:`DEFAULT_WORKERS` threads; no database transaction is open while S3
  answers): a failure is a version that is missing or is a delete marker,
  whose stored SHA-256 checksum (the full-object one, or the composite one of
  a multipart upload, as recorded), size or ETag differs from the record, that
  has no Object Lock retention, whose retain-until date is earlier than the
  recorded one, or whose retention from its upload (retain-until minus the
  ``LastModified`` that ``HeadObject`` reports) is shorter, by more than a
  day, than its bucket's retention floor; every ``non_conforming`` record;
  an ``erased`` record whose version still exists; and a record whose import
  outcome does not hold. The store is the ground truth for outcomes: an
  outcome that is not a straightforward import is RE-DERIVED from the
  version's body on every run (:func:`rederive_issues`) with the sync's own
  content check and plan (``plans``) and the same inputs - a transcript's
  agent and exit reason from its metadata or the sidecar version its record
  names, re-read; the body - that exact version, within its kind's limit,
  hashing to the record - is read and checked by the worker pool (at most
  :data:`REDERIVE_WINDOW_BYTES` in flight, so memory stays bounded however
  many records there are), the database part runs in the calling thread,
  and nothing is written. Neither a writer nor the portal's own database
  role can record an outcome the object does not prove:

  * from the database (:func:`outcome_issues`): the kind is its key's (an
    ``unmapped`` record is re-derived from its key alone), the status one a
    sync gives that kind; an ``ingested`` decision log has a current or
    superseded transcript version of its session imported from it with its
    SHA-256; an ``ingested`` pentest file has, in the store's namespace,
    exactly the findings it recorded importing under the ids its version
    gives them (their count and identity, recomputed from the findings'
    content - ``full``: re-derived from the body too), and no other finding
    of its file;
  * from the body: an ``unchanged`` decision log's entries are identical to,
    or a prefix of, its session's stored entries; an ``unchanged`` pentest
    file has no findings to store, or the store's namespace holds exactly
    them; a ``duplicate``'s counterpart holds exactly the findings of its
    body (and of its record), recomputed from the counterpart's content; a
    ``too_large`` version is over its kind's limit by the size
    ``HeadObject`` reports (a decision log: or its body over a transcript
    limit); a ``rejected`` version is still refused by its content check or
    its plan (a decision log by a dry run with the store's authority; a
    version of another kind is never refused for its content) - one that is
    not is a failure an administrator settles by acknowledging it. Every
    refusal (``rejected``, ``too_large``) is listed (``refusals``);
  * an ``acknowledged`` non-conforming version is still non-conforming by
    its own ``HeadObject`` (no SHA-256 checksum, or a body that does not
    match it).

  ``full`` also re-reads every body (streamed) and recomputes its SHA-256.
  Erased records (version absent) and acknowledged records (with the status
  they were acknowledged from; checked for existence, size and ETag, and
  SHA-256 - an acknowledged non-conforming one ``full`` only) are listed
  separately (informational); a version whose retain-until date has passed
  is listed as ``retention_expired`` (informational); an ``error`` record (a
  version a sync could not read or write yet, read again by every sync) is
  ``pending``, never a failure.
- **The store's pentest findings** (once per run,
  :func:`verify_store_findings`): every ``source_file`` of the store's
  namespace is held by a store object that imported it (an ingested record
  of its key, or one since erased, whose findings count it matches); any
  other is a failure - findings the database role wrote, not the store.
- **Documents** (once per run): every evidence document against its object
  record (the record exists, is an evidence document of the same key,
  SHA-256 and size, the document's kind matches its key) and every ingested
  evidence-document record has its document.
- **Store conflicts** (once per run, informational): decision-log exports
  the store authority refused because they differ from the stored
  transcript (``rejected``, detail ``conflict: ...``), listed for review as
  ``store_conflicts``; never a failure.
- **Listing** (every object version under the store's prefixes, page by
  page, one database query per page): a delete marker or a later version of
  a key is a failure; a key's first version the portal has not recorded is
  ``unrecorded``; a prefix whose listing fails is a failure (its error's
  class and code).

Status: ``broken`` (any failure), ``unverified`` (no failure, but
``unrecorded`` or ``pending`` > 0, or an erasure principal in the bucket
policy), else ``valid``. A SOC 2 evidence run requires ``valid`` after a
sync. At most :data:`MAX_KEPT` entries of a list are kept and
:data:`MAX_REPORTED` reported, each list with its exact ``<list>_count``.

A bounded run (the API) checks one slice per call - at most
``max_items`` records and at most ``max_bytes`` of bodies read (a slice
always checks at least one record), then at most ``max_items`` listed
versions, stopping only between keys - and returns a ``next_cursor`` to
continue with (``budget_exhausted``: the slice stopped at a budget); a run
is complete when ``next_cursor`` is null and is the sum of its slices. The
bucket is checked on every call, the documents, the store's findings and
the store conflicts on the first. An unbounded run (the CLI) checks
everything in one call, with the same bounded memory, and reports its
totals (``rederived``, ``bytes_read``).

Decision logs against the store (:func:`verify_decision_logs_against_store`)
-----------------------------------------------------------------------------
Every decision-log version imported from the store (``store_object_id``
set) must name a recorded decision-log object of its own session whose
SHA-256 equals the version's ``content_sha256``; that object must verify in
the store as above, and its body - that exact version, read streamed within
the transcript limits and the process's transcript import budget - must
hash to the record's SHA-256 and the version's, and parse (as an import
parses it) to the version's entry count and entries digest. Each object is
read once. A mismatch, a missing record or object, or an unreadable body
makes the result ``broken``; erased objects are listed separately. Sessions
are checked in id order; ``after_session`` / ``max_sessions`` bound and
resume a run.
"""

from __future__ import annotations

import base64
import collections
import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import bindparam, text

from app.services.evidence_store import PREFIXES, keys, store

MAX_REPORTED = 100
MAX_KEPT = 1000
DEFAULT_WORKERS = 4
RECORD_PAGE = 500
LOCK_MODES = ("GOVERNANCE", "COMPLIANCE")
RETENTION_TOLERANCE = timedelta(days=1)
MISSING = "the version is missing from the store"
IS_DELETE_MARKER = "the version is a delete marker"
CHECKSUM_DIFFERS = "the stored SHA-256 checksum differs from the record"
SECOND_VERSION = "a later version of a write-once key"
DELETE_MARKER = "a delete marker"
STILL_EXISTS = "recorded as erased, but the version still exists in the store"
RETENTION_EXPIRED = "retention_expired"
REQUIRED_DENIALS = ("s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention",
                    "s3:PutObjectRetention")
EXPIRING_LIFECYCLE = ("Expiration", "NoncurrentVersionExpiration", "Transitions", "Transition",
                      "NoncurrentVersionTransitions", "NoncurrentVersionTransition")
CURRENT_OR_SUPERSEDED = ("current", "superseded")
# The statuses a sync (or an administrator) gives a version of each kind.
OUTCOMES = {
    keys.KIND_DECISION_LOG: {"ingested", "unchanged"},
    keys.KIND_SIDECAR: {"recorded"},
    keys.KIND_PENTEST: {"ingested", "unchanged", "duplicate"},
    keys.KIND_DOCUMENT: {"ingested"},
    keys.KIND_UNMAPPED: {"recorded"},
}
_ANY_KIND = {"rejected", "non_conforming", "error", "acknowledged", "erased"}
_READ_KINDS = {keys.KIND_DECISION_LOG, keys.KIND_SIDECAR, keys.KIND_PENTEST, keys.KIND_DOCUMENT}
RECORD_SQL = (
    "SELECT o.id, o.bucket, o.key, o.key_escaped, o.version_id, o.kind, o.status, o.sha256, o.size, o.etag, "
    "o.last_modified, o.retain_until, o.lock_mode, o.detail, o.erased_at, o.erasure_reason, o.import_info, "
    "o.object_metadata, o.acknowledged_from, o.composite_checksum "
    "FROM evidence_store_objects o ")
_ARN_RE = re.compile(r"^arn:(?P<partition>aws[a-z-]*):s3:::(?P<rest>.*)$", re.DOTALL)
REGION_PARTITIONS = (("cn-", "aws-cn"), ("us-gov-", "aws-us-gov"))
# The outcomes re-derived from the version's body on every run (module docstring).
REDERIVED = ("unchanged", "duplicate", "rejected", "too_large")
REFUSALS = ("rejected", "too_large")
# Bodies re-derived at once (bytes and versions in flight between the worker pool and the database part).
REDERIVE_WINDOW_BYTES = 64 * 1024 * 1024
STORE_FINDINGS_PAGE = 1000
NOT_REPRODUCED = "an administrator acknowledges a refusal that no longer re-derives (evidence-store acknowledge)"


class Capped:
    """A list of findings that keeps at most ``cap`` items (default :data:`MAX_KEPT`) and counts them all."""

    def __init__(self, cap: int | None = None):
        self.cap = MAX_KEPT if cap is None else cap
        self.items: list = []
        self.count = 0

    def add(self, item) -> None:
        self.count += 1
        if len(self.items) < self.cap:
            self.items.append(item)

    def report(self, limit: int = MAX_REPORTED) -> list:
        return self.items[:limit]


@dataclass(frozen=True)
class RecordRow:
    id: str
    bucket: str
    key: str
    version_id: str
    kind: str
    status: str
    sha256: str | None
    size: int
    etag: str | None = None
    last_modified: object = None
    retain_until: object = None
    lock_mode: str | None = None
    detail: str | None = None
    erased_at: object = None
    erasure_reason: str | None = None
    key_escaped: bool = False
    import_info: object = None
    object_metadata: object = None
    acknowledged_from: str | None = None
    composite_checksum: str | None = None

    @property
    def s3_key(self) -> str:
        """The key S3 holds (the recorded key, unescaped)."""
        return keys.raw_key(self.key, bool(self.key_escaped))

    @property
    def info(self) -> dict:
        value = self.import_info
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                value = None
        return value if isinstance(value, dict) else {}

    @property
    def metadata(self) -> dict:
        value = self.object_metadata
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                value = None
        return value if isinstance(value, dict) else {}

    @property
    def acknowledged_non_conforming(self) -> bool:
        """An acknowledged non-conforming upload (its stored checksum is not its body's)."""
        return self.status == "acknowledged" and self.acknowledged_from in (None, "non_conforming")


def record_row(session, record_id: str) -> RecordRow | None:
    """The record ``record_id`` as verification reads it."""
    row = session.execute(text(RECORD_SQL + "WHERE o.id = :id"), {"id": record_id}).first()
    return RecordRow(**row._mapping) if row is not None else None


def _aware(value):
    if value is None or getattr(value, "tzinfo", None) is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


# ----------------------------------------------------------------------------
# Bucket
# ----------------------------------------------------------------------------

class _DuplicateKey(ValueError):
    pass


def _unique_keys(pairs):
    """``object_pairs_hook`` refusing a JSON object with a repeated key (a policy
    reader could see either value)."""
    found = {}
    for name, value in pairs:
        if name in found:
            raise _DuplicateKey(name)
        found[name] = value
    return found


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def _wildcard(pattern: str, value: str, *, ignore_case: bool = False) -> bool:
    """IAM matching: ``*`` any characters, ``?`` one character."""
    regex = "".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern)
    return re.fullmatch(regex, value, re.DOTALL | (re.IGNORECASE if ignore_case else 0)) is not None


def _everyone(principal) -> bool:
    if principal == "*":
        return True
    return isinstance(principal, dict) and set(principal) == {"AWS"} and "*" in _as_list(principal["AWS"])


def _covers_action(statement: dict, action: str) -> bool:
    return any(isinstance(item, str) and _wildcard(item, action, ignore_case=True)
               for item in _as_list(statement.get("Action")))


def partition_for_region(region: str | None) -> str:
    """The AWS partition of a region: ``aws-cn`` (``cn-*``), ``aws-us-gov`` (``us-gov-*``), else ``aws``."""
    for prefix, partition in REGION_PARTITIONS:
        if region and region.startswith(prefix):
            return partition
    return "aws"


def portal_partition(client=None) -> str:
    """The partition of the region the portal runs in (``AWS_REGION`` /
    ``AWS_DEFAULT_REGION``, else the S3 client's region)."""
    from app.services.aws_session import default_region

    region = default_region() or getattr(getattr(client, "meta", None), "region_name", None)
    return partition_for_region(region if isinstance(region, str) else None)


def resource_prefixes(resource, bucket: str, partition: str | None = None) -> set:
    """The store prefixes an object resource of a deny statement protects:
    ``arn:<partition>:s3:::<bucket>/*`` every one, ``arn:<partition>:s3:::<bucket>/<literal>*``
    (no ``*`` or ``?`` in the literal) each store prefix that starts with the
    literal; any other resource - one of another partition than ``partition``
    (default :func:`portal_partition`) included - none."""
    if not isinstance(resource, str):
        return set()
    match = _ARN_RE.match(resource)
    head = f"{bucket}/"
    if match is None or not match.group("rest").startswith(head) or not resource.endswith("*") \
            or match.group("partition") != (partition or portal_partition()):
        return set()
    literal = match.group("rest")[len(head):-1]
    if "*" in literal or "?" in literal:
        return set()
    return {prefix for prefix in PREFIXES if prefix.startswith(literal)}


def _covered_prefixes(statement: dict, bucket: str, partition: str) -> set:
    covered = set()
    for resource in _as_list(statement.get("Resource")):
        covered |= resource_prefixes(resource, bucket, partition)
    return covered


def _conditions(condition) -> dict | None:
    """``{(operator, key): [values]}`` of a condition block (lower-cased), or None when malformed."""
    if not isinstance(condition, dict):
        return None
    found = {}
    for operator, entries in condition.items():
        if not isinstance(entries, dict):
            return None
        for name, value in entries.items():
            found[(str(operator).lower(), str(name).lower())] = [str(v).lower() if isinstance(v, bool) else v
                                                                 for v in _as_list(value)]
    return found


def _erasure_principals(condition) -> list | None:
    """The principals of the documented erasure exception (``ArnNotEquals aws:PrincipalArn``), else None."""
    found = _conditions(condition)
    if not found or set(found) != {("arnnotequals", "aws:principalarn")}:
        return None
    principals = found[("arnnotequals", "aws:principalarn")]
    return principals if principals and all(isinstance(p, str) for p in principals) else None


def _if_none_match_condition(condition) -> bool:
    """True for no condition, or ``Null s3:if-none-match: true`` (with at most
    ``Bool s3:ObjectCreationOperation: true`` besides)."""
    if not condition:
        return True
    found = _conditions(condition)
    if not found or found.get(("null", "s3:if-none-match")) != ["true"]:
        return False
    return all(entry == ("null", "s3:if-none-match")
               or (entry == ("bool", "s3:objectcreationoperation") and values == ["true"])
               for entry, values in found.items())


def _uncovered(prefixes) -> str:
    return ", ".join(prefix for prefix in PREFIXES if prefix in prefixes)


def check_policy(policy_text: str | None, bucket: str, partition: str | None = None) -> tuple[list[str], list[str]]:
    """``(issues, erasure principals)`` of the bucket policy.

    A statement protects only with ``Effect`` exactly ``Deny``, ``Principal``
    ``"*"`` (or ``{"AWS": "*"}``), no ``NotAction`` / ``NotResource`` /
    ``NotPrincipal``, and object resources :func:`resource_prefixes` accepts
    (in ``partition``, default the portal's: :func:`portal_partition`).
    Each required action must be denied on every store prefix, without a
    condition or with only the documented erasure exception
    (``ArnNotEquals aws:PrincipalArn`` naming literal ARNs: one holding ``*``,
    ``?`` or ``$`` - a wildcard or a policy variable - fails); a ``PutObject``
    without ``If-None-Match`` must be denied on every store prefix. A policy
    that is not JSON, or repeats a key in any object, fails.
    """
    partition = partition or portal_partition()
    if policy_text is None:
        return ["the bucket has no bucket policy"], []
    try:
        policy = json.loads(policy_text, object_pairs_hook=_unique_keys)
    except _DuplicateKey as exc:
        return [f"the bucket policy repeats the key {keys.display(str(exc), 60)!r} in an object"], []
    except (TypeError, ValueError, RecursionError):
        return ["the bucket policy is not valid JSON"], []
    if not isinstance(policy, dict):
        return ["the bucket policy has no statements"], []
    statements = policy.get("Statement")
    statements = [statements] if isinstance(statements, dict) else statements if isinstance(statements, list) else []
    denies = [(s, _covered_prefixes(s, bucket, partition)) for s in statements
              if isinstance(s, dict) and s.get("Effect") == "Deny" and _everyone(s.get("Principal"))
              and not {"NotAction", "NotResource", "NotPrincipal"} & set(s)]
    issues, principals = [], []
    for action in REQUIRED_DENIALS:
        missing = set()
        for prefix in PREFIXES:
            unconditional, excepted = False, []
            for statement, covered in denies:
                if prefix not in covered or not _covers_action(statement, action):
                    continue
                if not statement.get("Condition"):
                    unconditional = True
                    break
                excepted += _erasure_principals(statement["Condition"]) or []
            if unconditional:
                continue
            if excepted:
                principals += [p for p in excepted if p not in principals]
            else:
                missing.add(prefix)
        if missing:
            issues.append(f"the bucket policy does not deny {action} on the bucket's objects to every principal "
                          f"(not under {_uncovered(missing)})")
    for principal in principals:
        if any(ch in principal for ch in "*?$"):
            issues.append(f"the erasure exception names a wildcard principal or a policy variable "
                          f"({keys.display(principal, 200)})")
    unguarded = {prefix for prefix in PREFIXES
                 if not any(prefix in covered and _covers_action(statement, "s3:PutObject")
                            and _if_none_match_condition(statement.get("Condition")) for statement, covered in denies)}
    if unguarded:
        issues.append("the bucket policy does not deny a PutObject without If-None-Match to every principal "
                      f"(not under {_uncovered(unguarded)})")
    return issues, principals


def check_lifecycle(rules) -> list[str]:
    """The lifecycle rules that would expire or transition versions."""
    issues = []
    for rule in rules or []:
        if not isinstance(rule, dict):
            continue
        actions = [name for name in EXPIRING_LIFECYCLE if rule.get(name)]
        if actions:
            issues.append(f"lifecycle rule {keys.display(str(rule.get('ID') or ''), 100)!r} would expire or "
                          f"transition versions ({', '.join(actions)})")
    return issues


def retention_floors(session) -> dict:
    """``{bucket: floor in days}`` of every bucket with a retention floor (its latest row)."""
    floors = dict(session.execute(text(
        "SELECT f.bucket, f.days FROM evidence_store_retention_floors f WHERE NOT EXISTS ("
        "SELECT 1 FROM evidence_store_retention_floors g WHERE g.bucket = f.bucket "
        "AND (g.set_at > f.set_at OR (g.set_at = f.set_at AND g.id > f.id)))")).all())
    session.rollback()
    return floors


def retention_floor_history(session, bucket: str) -> dict:
    """The bucket's retention floors in time order: every lowering (informational,
    ``lowerings``) and the ``issues`` of its history - its first floor must be the
    default retention its first sync observed (the first run that read one)."""
    rows = session.execute(text(
        "SELECT days, set_at, set_by, reason FROM evidence_store_retention_floors WHERE bucket = :bucket "
        "ORDER BY set_at, id"), {"bucket": bucket}).all()
    first_run = session.execute(text(
        "SELECT id, retention_days FROM evidence_store_sync_runs WHERE bucket = :bucket "
        "AND retention_days IS NOT NULL ORDER BY queued_at, id LIMIT 1"), {"bucket": bucket}).first()
    session.rollback()
    lowerings = [{"from_days": earlier.days, "to_days": later.days, "set_at": later.set_at, "set_by": later.set_by,
                  "reason": later.reason}
                 for earlier, later in zip(rows, rows[1:]) if later.days < earlier.days]
    issues = []
    if rows and first_run is not None and rows[0].days != first_run.retention_days:
        issues.append(f"the bucket's first retention floor ({rows[0].days} days) is not the default retention its "
                      f"first sync observed ({first_run.retention_days} days, run {first_run.id})")
    return {"lowerings": lowerings, "issues": issues, "first_days": rows[0].days if rows else None}


def first_floor_issues(session, client, bucket: str, first_days: int | None) -> list[str]:
    """The bucket's first retention floor against the store: it is no lower than
    the Object Lock retention, from its upload (retain-until minus the
    ``LastModified`` ``HeadObject`` reports), of the earliest version the portal
    recorded in the bucket (records are dated by the database clock), less one
    day and one more per four years (leap days of a period set in years). A
    version that cannot be read is reported by its own record's check."""
    if not first_days:
        return []
    row = session.execute(text(
        "SELECT key, key_escaped, version_id FROM evidence_store_objects WHERE bucket = :bucket "
        "AND status <> 'erased' ORDER BY created_at, id LIMIT 1"), {"bucket": bucket}).first()
    session.rollback()
    if row is None:
        return []
    try:
        head = store.head_version(client, bucket, keys.raw_key(row.key, bool(row.key_escaped)), row.version_id)
    except Exception:  # noqa: BLE001 - the record's own check reports it
        return []
    until, uploaded = _aware(head.get("ObjectLockRetainUntilDate")), _aware(head.get("LastModified"))
    if head.get("ObjectLockMode") not in LOCK_MODES or until is None or uploaded is None:
        return []
    retention = until - uploaded
    tolerance = RETENTION_TOLERANCE + timedelta(days=-(-retention.days // 1461))
    if timedelta(days=first_days) < retention - tolerance:
        return [f"the bucket's first retention floor ({first_days} days) is below the Object Lock retention "
                f"({retention.days} days from its upload) of the earliest version the portal recorded "
                f"({keys.display(row.key, 200)}): the first floor is not the default retention of the bucket's "
                "first sync"]
    return []


def _has_records(session, bucket: str) -> bool:
    found = session.execute(text("SELECT 1 FROM evidence_store_objects WHERE bucket = :bucket LIMIT 1"),
                            {"bucket": bucket}).first() is not None
    session.rollback()
    return found


def check_bucket(client, bucket: str, *, floor_days: int | None = None, floor_required: bool = False) -> dict:
    """The bucket's versioning, Object Lock (against its retention floor),
    policy and lifecycle, with ``issues`` and ``erasure_principals`` (module
    docstring). ``floor_required``: the bucket has records, so it must have a floor."""
    result = {"versioning": None, "object_lock": None, "default_retention": None, "issues": [],
              "erasure_principals": [], "lifecycle_rules": None, "retention_floor_days": floor_days}
    issues = result["issues"]
    try:
        settings = store.bucket_settings(client, bucket)
    except Exception as exc:  # noqa: BLE001 - reported, never a crash
        issues.append(f"the bucket's configuration cannot be read ({store.describe(exc)})")
        settings = None
    if settings is not None:
        result.update(settings)
        retention = settings["default_retention"] or {}
        period = retention.get("period_days")
        if settings["versioning"] != "Enabled":
            issues.append("versioning is not enabled")
        if not settings["object_lock"]:
            issues.append("Object Lock is not enabled")
        elif not retention or not period:
            issues.append("Object Lock has no default retention")
        elif retention.get("mode") not in LOCK_MODES:
            issues.append(f"the default retention mode {retention.get('mode')!r} is not GOVERNANCE or COMPLIANCE")
        elif floor_days and period < floor_days:
            issues.append(f"the default retention ({period} days) is below the retention floor of {floor_days} days")
    if floor_days is None and floor_required:
        issues.append("the bucket has records but no retention floor (a sync sets it from the default retention)")
    try:
        policy_issues, result["erasure_principals"] = check_policy(store.bucket_policy(client, bucket), bucket,
                                                                   portal_partition(client))
        issues += policy_issues
    except Exception as exc:  # noqa: BLE001 - reported, never a crash
        issues.append(f"the bucket policy cannot be read ({store.describe(exc)})")
    try:
        rules = store.bucket_lifecycle(client, bucket)
        result["lifecycle_rules"] = len(rules)
        issues += check_lifecycle(rules)
    except Exception as exc:  # noqa: BLE001 - reported, never a crash
        issues.append(f"the bucket's lifecycle configuration cannot be read ({store.describe(exc)})")
    return result


# ----------------------------------------------------------------------------
# Records
# ----------------------------------------------------------------------------

def _head(client, record: RecordRow):
    """``(head, issue)``: the version's ``HeadObject``, or why there is none."""
    try:
        head = store.head_version(client, record.bucket, record.s3_key, record.version_id)
    except Exception as exc:  # noqa: BLE001 - classified below
        if store.is_missing(exc):
            return None, MISSING
        if store.is_delete_marker(exc):
            return None, IS_DELETE_MARKER
        return None, f"the version cannot be read ({store.describe(exc)})"
    if head.get("DeleteMarker"):
        return None, IS_DELETE_MARKER
    return head, None


def check_version(client, record: RecordRow, *, full: bool = False, floor_days: int | None = None,
                  now: datetime | None = None) -> list[str]:
    """The issues of one recorded version in the store (empty: it verifies).
    :data:`RETENTION_EXPIRED` among them is informational, never a failure.
    The retention from upload is measured from the ``LastModified`` S3
    reports, never from the record."""
    head, missing = _head(client, record)
    if missing:
        return [missing]
    issues = []
    if not record.acknowledged_non_conforming and (record.sha256 is not None
                                                   or record.composite_checksum is not None):
        checksum = store.stored_checksum(head)
        if checksum.problem:
            issues.append(checksum.problem)
        elif record.composite_checksum is not None:
            if checksum.composite != record.composite_checksum:
                issues.append(CHECKSUM_DIFFERS)
        elif checksum.sha256 != record.sha256:
            issues.append(CHECKSUM_DIFFERS)
    size = int(head.get("ContentLength") or 0)
    if size != record.size:
        issues.append(f"the stored size ({size}) differs from the record ({record.size})")
    if record.etag and head.get("ETag") != record.etag:
        issues.append("the stored ETag differs from the record")
    mode, until = head.get("ObjectLockMode"), _aware(head.get("ObjectLockRetainUntilDate"))
    expired = False
    if mode not in LOCK_MODES or until is None:
        issues.append("the version is not under Object Lock retention")
    else:
        recorded_until = _aware(record.retain_until)
        if recorded_until is not None and until < recorded_until:
            issues.append("its retain-until date is earlier than the recorded one")
        uploaded = _aware(head.get("LastModified"))
        if floor_days and uploaded is None:
            issues.append("the store reports no upload time for the version")
        elif floor_days and until - uploaded < timedelta(days=floor_days) - RETENTION_TOLERANCE:
            issues.append(f"its Object Lock retention ({(until - uploaded).days} days from its upload) is shorter "
                          f"than the retention floor of {floor_days} days")
        expired = until <= (now or datetime.now(timezone.utc))
    if record.acknowledged_non_conforming and not issues:
        issues += _still_non_conforming(client, record, head)
    if full and not issues and record.sha256 is not None:
        try:
            digest, _ = store.hash_version(client, record.bucket, record.s3_key, record.version_id, max(size, 1))
        except Exception as exc:  # noqa: BLE001 - reported per version
            return [f"the body cannot be read ({store.describe(exc)})"]
        if digest != record.sha256:
            issues.append("the body's SHA-256 differs from the record")
    return issues + ([RETENTION_EXPIRED] if expired else [])


def _still_non_conforming(client, record: RecordRow, head: dict) -> list[str]:
    """An acknowledged version is non-conforming by its own ``HeadObject``: no
    SHA-256 checksum (or a malformed one), or (within its kind's limit) a body
    that does not match it - a full-object checksum's SHA-256, a composite
    checksum's size. A version that conforms was never one to acknowledge."""
    from app.services.evidence_store.sync import kind_limit

    checksum = store.stored_checksum(head)
    if checksum.problem:
        return []
    limit, size = kind_limit(record.kind), int(head.get("ContentLength") or 0)
    if limit is not None and size <= limit:
        try:
            digest, read = store.hash_version(client, record.bucket, record.s3_key, record.version_id, limit)
        except Exception as exc:  # noqa: BLE001 - reported per version
            return [f"the body cannot be read to re-derive its non-conformance ({store.describe(exc)})"]
        if read != size or (checksum.composite is None and digest != checksum.sha256):
            return []
    kind = "a composite" if checksum.composite is not None else "a full-object"
    return [f"recorded as non-conforming, but the version has {kind} SHA-256 checksum"
            + (" its body matches" if limit is not None and size <= limit else "")]


def _item(record: RecordRow, issue: str) -> dict:
    return {"id": record.id, "bucket": record.bucket, "key": keys.display(record.key),
            "version_id": record.version_id, "status": record.status, "issue": issue}


def _summary(record: RecordRow, **extra) -> dict:
    return dict({"id": record.id, "bucket": record.bucket, "key": keys.display(record.key),
                 "version_id": record.version_id}, **extra)


def _check_record(client, record: RecordRow, full: bool, floors: dict) -> tuple[str, list[str]]:
    """``(category, issues)`` of one record: ``erased``, ``pending``, ``acknowledged`` or ``checked``."""
    if record.status == "erased":
        _, missing = _head(client, record)
        if missing in (MISSING, IS_DELETE_MARKER):
            return "erased", []
        return "erased", [missing or STILL_EXISTS]
    if record.status == "error":
        _, missing = _head(client, record)
        return "pending", [missing] if missing else []
    category = "acknowledged" if record.status == "acknowledged" else "checked"
    return category, check_version(client, record, full=full, floor_days=floors.get(record.bucket))


# -- import outcomes ----------------------------------------------------------

def _session_of(record: RecordRow) -> str | None:
    return keys.classify(record.s3_key).session_id


def _store_holder(record: RecordRow) -> str | None:
    from app.services.evidence_store.plans import store_holder
    from cli.loaders.base import SkipRecord
    from cli.loaders.pentest_findings import PentestFindingsLoader

    try:
        return store_holder(PentestFindingsLoader.source_file_for(record.s3_key)[0])
    except SkipRecord:
        return None


def _rows(session, sql: str, name: str, values) -> list:
    if not values:
        return []
    return session.execute(text(sql).bindparams(bindparam(name, expanding=True)), {name: sorted(values)}).all()


def outcome_facts(session, records) -> dict:
    """What the database holds for the import outcomes of ``records`` that are
    checked without their bodies (a few bounded queries per page): the
    transcript versions imported from each ingested decision log, and what the
    store's namespace holds for each ingested pentest file against that
    record's version, recomputed from the findings' content
    (``plans.store_holdings``)."""
    from app.services.evidence_store.plans import store_holdings

    ingested = {r.id for r in records if r.kind == keys.KIND_DECISION_LOG and r.status == "ingested"}
    versions = {holder: r.version_id for r in records if r.kind == keys.KIND_PENTEST and r.status == "ingested"
                for holder in [_store_holder(r)] if holder}
    facts = {"by_object": collections.defaultdict(list)}
    for row in _rows(session, "SELECT store_object_id, session_id, content_sha256, status "
                              "FROM decision_log_transcripts WHERE store_object_id IN :ids", "ids", ingested):
        facts["by_object"][row.store_object_id].append(row)
    facts["holdings"] = store_holdings(versions)
    session.rollback()
    return facts


def outcome_issues(record: RecordRow, facts: dict) -> list[str]:
    """Why the database does not hold ``record``'s import outcome, from the
    database alone (empty: it does; module docstring). The outcomes in
    :data:`REDERIVED` are re-derived from the body by :func:`rederive_issues`."""
    classified = keys.classify(record.s3_key)
    if classified.kind != record.kind:
        return [f"the record's kind ({record.kind}) is not its key's ({classified.kind})"]
    allowed = OUTCOMES.get(record.kind, set()) | _ANY_KIND | ({"too_large"} if record.kind in _READ_KINDS else set())
    if record.status not in allowed:
        return [f"no sync records a {record.kind} version as {record.status}"]
    if record.kind == keys.KIND_DECISION_LOG and record.status == "ingested":
        if not any(v.session_id == classified.session_id and v.content_sha256 == record.sha256
                   and v.status in CURRENT_OR_SUPERSEDED for v in facts["by_object"].get(record.id, ())):
            return ["recorded ingested, but no current or superseded transcript version of its session was "
                    "imported from it"]
    elif record.kind == keys.KIND_PENTEST and record.status == "ingested":
        held = facts["holdings"].get(_store_holder(record))
        info = record.info
        if held is None:
            return ["recorded ingested, but the store's namespace holds no findings for its file"]
        issues = []
        if info.get("stored") is not True or not held.consistent \
                or (held.count, held.identity) != (info.get("findings"), info.get("identity_sha256")):
            issues.append("recorded ingested, but the store's namespace does not hold exactly the findings it "
                          "imported (their count and identity, recomputed from their content)")
        if held.extra:
            issues.append(f"the store's namespace holds {held.extra} finding(s) for its file that this version did "
                          "not import")
        return issues
    return []


def _body(client, record: RecordRow, limit: int) -> tuple[bytes | None, list[str]]:
    """The version's body, checked against the record's SHA-256, or the issue that stops it."""
    try:
        content = store.read_version(client, record.bucket, record.s3_key, record.version_id, limit)
    except store.BodyTooLarge as exc:
        return None, [f"the body is larger than the {record.kind} limit of {exc.limit} bytes"]
    except Exception as exc:  # noqa: BLE001 - reported per version
        return None, [f"the body cannot be read to re-derive its outcome ({store.describe(exc)})"]
    if hashlib.sha256(content).hexdigest() != record.sha256:
        return None, ["the body's SHA-256 differs from the record"]
    return content, []


def _without_body(record: RecordRow, full: bool) -> list[str] | None:
    """The re-derivation of an outcome that needs no body (its issues), or None
    when it is re-derived from the body (module docstring)."""
    from app.services.evidence_store.sync import kind_limit

    status, kind = record.status, record.kind
    limit = kind_limit(kind)
    if status == "too_large":
        if limit is not None and record.size > limit:
            return []  # over its kind's limit (the size HeadObject reports equals the record's)
        if kind != keys.KIND_DECISION_LOG:
            return [f"recorded too_large, but its {record.size} bytes are within the {kind} limit of {limit} bytes"]
        return None
    if status == "rejected" and kind not in (keys.KIND_DECISION_LOG, keys.KIND_PENTEST):
        return [f"recorded rejected, but a sync never refuses the content of a {kind} version"]
    if kind in (keys.KIND_DECISION_LOG, keys.KIND_PENTEST) and status in REDERIVED:
        return None
    if full and status == "ingested" and kind == keys.KIND_PENTEST:
        return None
    return []


@dataclass
class _Prepared:
    """What a worker read and checked of a version's body for its re-derivation
    (no database access): final ``issues``, or the content check's ``refusal``
    or ``checked`` result."""

    issues: list | None = None
    refusal: Exception | None = None
    checked: object = None
    content: bytes | None = None
    bytes_read: int = 0


def _decision_log_inputs(client, record: RecordRow) -> tuple[str | None, str | None, str | None]:
    """``(exit_reason, agent, issue)``: what the sync's content check of a transcript
    was given - its ``agent`` / ``exit-reason`` metadata, else the sidecar version
    its record names (when the sync read it), re-read now."""
    from app.services.evidence_store.sync import read_sidecar

    metadata = record.metadata
    exit_reason, agent = metadata.get("exit-reason"), metadata.get("agent")
    sidecar = record.info.get("sidecar")
    if (exit_reason is None or agent is None) and isinstance(sidecar, dict) and sidecar.get("read") is True:
        try:
            side_reason, side_agent = read_sidecar(client, record.bucket, sidecar.get("key"),
                                                   sidecar.get("version_id"))
        except Exception as exc:  # noqa: BLE001 - reported per version
            return None, None, f"its sidecar cannot be read to re-derive its outcome ({store.describe(exc)})"
        exit_reason, agent = exit_reason or side_reason, agent or side_agent
    return exit_reason, agent, None


def _prepare(client, record: RecordRow) -> _Prepared:
    """Read a version's body (that exact version, within its kind's limit, hashing
    to the record) and run its kind's content check: the part of a
    re-derivation the worker pool does, without the database."""
    from app.services.evidence_import_decision_logs import import_slot
    from app.services.evidence_store import plans
    from app.services.evidence_store.sync import PENTEST_MAX_VALUES, kind_limit, parse_json

    if record.kind == keys.KIND_DECISION_LOG:
        with import_slot(size=record.size):
            content, issues = _body(client, record, kind_limit(record.kind))
            if content is None:
                return _Prepared(issues=issues)
            exit_reason, agent, problem = _decision_log_inputs(client, record)
            if problem:
                return _Prepared(issues=[problem], bytes_read=len(content))
            try:
                checked = plans.check_decision_log(content, record.s3_key, exit_reason, agent)
            except plans.ContentRejected as exc:
                return _Prepared(refusal=exc, bytes_read=len(content))
            return _Prepared(checked=checked, content=content, bytes_read=len(content))
    content, issues = _body(client, record, kind_limit(record.kind))
    if content is None:
        return _Prepared(issues=issues)
    try:
        parsed = parse_json(content, max_values=PENTEST_MAX_VALUES)
        return _Prepared(checked=plans.check_pentest(record.s3_key, parsed, record.version_id),
                         bytes_read=len(content))
    except plans.ContentRejected as exc:
        return _Prepared(refusal=exc, bytes_read=len(content))


def _finish_decision_log(session, record: RecordRow, prepared: _Prepared) -> list[str]:
    from app.services import evidence_import_decision_logs as decision_logs
    from app.services.evidence_store import plans

    status, refusal = record.status, prepared.refusal
    if status == "too_large":
        if isinstance(refusal, plans.TooLarge):
            return []
        return ["recorded too_large, but its body is within the decision-log limits"]
    if status == "rejected":
        if refusal is not None:
            return []
        result = plans.plan_decision_log(prepared.checked, prepared.content, record.s3_key, record.id)
        if result.status == "rejected":
            return []
        return [f"recorded rejected, but an import of its body is not refused (it would be {result.status}); "
                + NOT_REPRODUCED]
    if refusal is not None:
        return [f"recorded unchanged, but its body is refused ({keys.display(str(refusal), 200)})"]
    session_id, entries = prepared.checked.session_id, prepared.checked.parsed.entries
    exists = session.execute(text("SELECT 1 FROM decision_log_sessions WHERE id = :s"), {"s": session_id}).first()
    if exists is None:
        return ["recorded unchanged, but its session does not exist"]
    comparison = decision_logs._compare_with_stored(session_id, entries)
    if comparison.difference is not None or len(entries) > comparison.stored:
        return ["recorded unchanged, but its entries are not identical to, or a prefix of, its session's stored "
                "entries"]
    return []


def _finish_pentest(session, record: RecordRow, prepared: _Prepared) -> list[str]:  # noqa: ARG001
    from app.services.evidence_import import held_findings
    from app.services.evidence_store import plans

    status, info, refusal, checked = record.status, record.info, prepared.refusal, prepared.checked
    if refusal is not None:
        if status == "rejected":
            return []
        return [f"recorded {status}, but an import of its body refuses it ({keys.display(str(refusal), 200)})"]
    found = (checked.count, checked.identity) if checked.rows is not None else (None, None)
    if status == "duplicate":
        holder = info.get("duplicate_of")
        held = held_findings([holder]).get(holder) if isinstance(holder, str) and checked.count else None
        if held is None or not held.matches(checked.count, checked.identity) \
                or found != (info.get("findings"), info.get("identity_sha256")):
            return ["recorded duplicate, but its counterpart does not hold exactly the findings of its body"]
        return []
    if status == "ingested":
        if found != (info.get("findings"), info.get("identity_sha256")):
            return ["recorded ingested, but the findings of its body are not the ones it recorded importing"]
        return []
    try:
        plan = plans.plan_pentest(checked)
    except plans.Conflict as exc:
        if status == "rejected":
            return []
        return [f"recorded {status}, but an import of its body refuses it ({keys.display(str(exc), 200)})"]
    if status == "rejected":
        return [f"recorded rejected, but an import of its body is not refused (it would be {plan.outcome}); "
                + NOT_REPRODUCED]
    if status == "unchanged" and plan.outcome != plans.UNCHANGED:
        return ["recorded unchanged, but the store's namespace does not hold exactly the findings of its body "
                f"(an import would be {plan.outcome})"]
    return []


def _finish(session, record: RecordRow, prepared: _Prepared) -> list[str]:
    """The database part of a re-derivation (in the calling thread; writes nothing)."""
    if prepared.issues is not None:
        return prepared.issues
    try:
        if record.kind == keys.KIND_DECISION_LOG:
            return _finish_decision_log(session, record, prepared)
        return _finish_pentest(session, record, prepared)
    except Exception as exc:  # noqa: BLE001 - reported per version, never a crash
        return [f"its outcome cannot be re-derived from its body ({store.describe(exc)})"]
    finally:
        session.rollback()


def rederive_issues(session, client, record: RecordRow, *, full: bool = False) -> list[str]:
    """Re-derive ``record``'s outcome from its version's body (module docstring):
    every outcome in :data:`REDERIVED`, and with ``full`` an ingested pentest
    file's findings - with the sync's own content check and plan
    (``plans``) and the same inputs. The body - that exact version, within its
    kind's limit, hashing to the record's SHA-256 - is read before any
    database access; the re-derivation writes nothing."""
    quick = _without_body(record, full)
    if quick is not None:
        return quick
    return _finish(session, record, _prepare(client, record))


def _rederived(pool, session, client, records, workers: int):
    """``(issues, bytes read)`` of each of ``records`` (needing their bodies), in
    order: bodies read and checked by ``pool`` - at most
    :data:`REDERIVE_WINDOW_BYTES` and twice ``workers`` versions in flight -
    and the database part here."""
    window = collections.deque()
    inflight = 0

    def finish(entry):
        record, future, _ = entry
        try:
            prepared = future.result()
        except Exception as exc:  # noqa: BLE001 - reported per version, never a crash
            return [f"its outcome cannot be re-derived from its body ({store.describe(exc)})"], 0
        return _finish(session, record, prepared), prepared.bytes_read

    for record in records:
        cost = max(int(record.size or 0), 1)
        while window and (inflight + cost > REDERIVE_WINDOW_BYTES or len(window) >= 2 * max(1, workers)):
            entry = window.popleft()
            inflight -= entry[2]
            yield finish(entry)
        window.append((record, pool.submit(_prepare, client, record), cost))
        inflight += cost
    while window:
        yield finish(window.popleft())


def _cost(record: RecordRow, full: bool) -> int:
    """The bytes a record's check reads at most: its body re-derived, and with
    ``full`` re-hashed."""
    from app.services.evidence_store.sync import SIDECAR_LIMIT

    cost = 0
    if full and record.sha256 is not None and record.status not in ("erased", "error", "non_conforming"):
        cost += int(record.size or 0)
    if _without_body(record, full) is None:
        cost += int(record.size or 0) + (SIDECAR_LIMIT if record.info.get("sidecar") else 0)
    return cost


def _within_budget(rows: list, full: bool, remaining: int, progress: bool) -> list:
    """The leading ``rows`` whose bytes fit ``remaining`` (the first always when
    nothing has been checked yet, so every slice makes progress)."""
    taken = []
    for record in rows:
        cost = _cost(record, full)
        if cost > remaining and (taken or progress):
            break
        taken.append(record)
        remaining -= cost
    return taken


def verify_records(session, client, *, full: bool = False, after_id: str | None = None,
                   max_records: int | None = None, workers: int = DEFAULT_WORKERS, floors: dict | None = None,
                   max_bytes: int | None = None) -> dict:
    """Check every record (of every bucket) after ``after_id`` - at most
    ``max_records``, and at most ``max_bytes`` of bodies read (``budget_exhausted``:
    the slice stopped there; ``next_after_id`` continues) - with ``HeadObject``
    and the re-derivation of its outcome, both through a pool of ``workers``
    threads; memory stays bounded however many records there are."""
    found = {name: Capped() for name in ("failures", "erased", "acknowledged", "pending", "retention_expired",
                                         "refusals")}
    checked = rederived = bytes_read = planned = 0
    after = after_id or ""
    next_after = None
    exhausted = False
    floors = retention_floors(session) if floors is None else floors
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        while True:
            limit = RECORD_PAGE if max_records is None else min(RECORD_PAGE, max_records - checked)
            if limit <= 0:
                next_after = after
                break
            page = [RecordRow(**row._mapping) for row in session.execute(text(
                RECORD_SQL + "WHERE o.id > :after ORDER BY o.id LIMIT :limit"), {"after": after, "limit": limit})]
            session.rollback()  # no snapshot is held while S3 answers
            if not page:
                break
            rows = page
            if max_bytes is not None:
                rows = _within_budget(page, full, max_bytes - planned, progress=checked > 0)
                planned += sum(_cost(record, full) for record in rows)
                if not rows:
                    next_after, exhausted = after, True
                    break
            facts = outcome_facts(session, rows)
            to_check = []
            for record in rows:
                if record.status in REFUSALS:
                    found["refusals"].add(_summary(record, kind=record.kind, status=record.status,
                                                   detail=record.detail))
                outcome = outcome_issues(record, facts)
                for issue in outcome:
                    found["failures"].add(_item(record, issue))
                if record.status == "non_conforming":
                    found["failures"].add(_item(record, f"recorded non_conforming: {record.detail or ''}".strip()))
                else:
                    to_check.append((record, bool(outcome)))
            results = list(pool.map(lambda pair: _check_record(client, pair[0], full, floors), to_check))
            entries = []
            for (record, outcome_failed), (category, issues) in zip(to_check, results):
                if full and category in ("checked", "acknowledged") and record.sha256 is not None:
                    bytes_read += int(record.size or 0)
                ready = not outcome_failed and category == "checked" \
                    and not [issue for issue in issues if issue != RETENTION_EXPIRED]
                entries.append([record, category, list(issues), _without_body(record, full) if ready else []])
            bodies = [entry for entry in entries if entry[3] is None]
            outcomes = _rederived(pool, session, client, [entry[0] for entry in bodies], workers)
            for entry, (issues, read) in zip(bodies, outcomes):
                entry[3], rederived, bytes_read = issues, rederived + 1, bytes_read + read
            for record, category, issues, outcome in entries:
                for issue in issues + outcome:
                    if issue == RETENTION_EXPIRED:
                        found["retention_expired"].add(_summary(record, retain_until=record.retain_until))
                    else:
                        found["failures"].add(_item(record, issue))
                if category == "erased" and not issues:
                    found["erased"].add(_summary(record, erased_at=record.erased_at, reason=record.erasure_reason))
                elif category == "acknowledged" and not [i for i in issues if i != RETENTION_EXPIRED]:
                    found["acknowledged"].add(_summary(record, acknowledged_from=record.acknowledged_from or
                                                       "non_conforming", detail=record.detail))
                elif category == "pending":
                    found["pending"].add(_summary(record, detail=record.detail))
            checked += len(rows)
            after = rows[-1].id
            if len(rows) < len(page):
                next_after, exhausted = after, True
                break
            if len(page) < limit:
                break
    if next_after is not None:
        remaining = session.execute(text("SELECT 1 FROM evidence_store_objects WHERE id > :after LIMIT 1"),
                                    {"after": next_after}).first()
        session.rollback()
        next_after = next_after if remaining else None
        exhausted = exhausted and next_after is not None
    result = {"checked": checked, "next_after_id": next_after, "rederived": rederived, "bytes_read": bytes_read,
              "budget_exhausted": exhausted}
    for name, items in found.items():
        result[name] = items.report()
        result[f"{name}_count"] = items.count
    result["failure_count"] = result.pop("failures_count")
    return result


def verify_store_findings(session) -> dict:
    """Every finding of the store's namespace is held by a store object that
    imported it: a ``source_file`` no backing record (``plans.backing_records``)
    accounts for is a failure, and so is one whose rows outnumber what its
    erased backing record imported (an ingested one is checked with its
    record). One query per :data:`STORE_FINDINGS_PAGE` source files."""
    from app.services.evidence_store.plans import backing_records

    failures, holders, findings, after = Capped(), 0, 0, ""
    while True:
        page = session.execute(text(
            "SELECT source_file, count(*) AS n FROM pentest_findings WHERE source_file LIKE 'evidence-store:%' "
            "AND source_file > :after GROUP BY source_file ORDER BY source_file LIMIT :limit"),
            {"after": after, "limit": STORE_FINDINGS_PAGE}).all()
        if not page:
            session.rollback()
            break
        paths = {row.source_file: row.source_file.split(":", 1)[1] for row in page}
        backing = backing_records(paths.values())
        session.rollback()
        for row in page:
            holders, findings = holders + 1, findings + row.n
            records = backing.get(paths[row.source_file])
            if not records:
                failures.add({"source_file": keys.display(row.source_file), "findings": row.n,
                              "issue": "findings in the store's namespace that no store object imported (no "
                                       f"ingested record of pentest-evidence/{keys.display(paths[row.source_file])})"})
            elif records[0].status == "erased" and row.n != records[0].count:
                failures.add({"source_file": keys.display(row.source_file), "findings": row.n,
                              "issue": f"the store's namespace holds {row.n} finding(s) for the file; the store "
                                       f"object that imported them (since erased) imported {records[0].count}"})
        after = page[-1].source_file
        if len(page) < STORE_FINDINGS_PAGE:
            break
    return {"source_files": holders, "findings": findings, "failures": failures.report(),
            "failure_count": failures.count}


_DOCUMENT_MISMATCH = (
    "FROM evidence_documents d LEFT JOIN evidence_store_objects o ON o.id = d.store_object_id "
    "WHERE o.id IS NULL OR o.kind <> 'evidence_document' OR o.key <> d.key "
    "OR o.sha256 IS DISTINCT FROM d.sha256 OR o.size <> d.size OR o.status NOT IN ('ingested', 'erased') "
    "OR d.kind <> CASE WHEN d.key LIKE 'codex-reviews/%' THEN 'code-review' "
    "WHEN d.key LIKE 'pentest-reports/%' THEN 'pentest-report' "
    "WHEN d.key LIKE 'evidence/artifacts/%' THEN 'evidence-artifact' ELSE '' END ")
_ORPHAN_OBJECTS = (
    "FROM evidence_store_objects o WHERE o.kind = 'evidence_document' AND o.status = 'ingested' "
    "AND NOT EXISTS (SELECT 1 FROM evidence_documents d WHERE d.store_object_id = o.id) ")
_STORE_CONFLICTS = (
    "FROM evidence_store_objects o WHERE o.kind = 'decision_log' AND o.status = 'rejected' "
    "AND o.detail LIKE 'conflict:%' ")


def verify_documents(session) -> dict:
    """Every evidence document against its object record, and every ingested
    evidence-document record against its document (two bounded queries each)."""
    checked = session.execute(text("SELECT count(*) FROM evidence_documents")).scalar() or 0
    mismatched = session.execute(text("SELECT count(*) " + _DOCUMENT_MISMATCH)).scalar() or 0
    orphaned = session.execute(text("SELECT count(*) " + _ORPHAN_OBJECTS)).scalar() or 0
    failures = [{"document_id": row.id, "key": keys.display(row.key), "store_object_id": row.store_object_id,
                 "issue": "the document differs from its object record" if row.object_id
                 else "the document's object record is missing"}
                for row in session.execute(text(
                    "SELECT d.id, d.key, d.store_object_id, o.id AS object_id " + _DOCUMENT_MISMATCH
                    + "ORDER BY d.id LIMIT :limit"), {"limit": MAX_REPORTED})]
    failures += [{"document_id": None, "key": keys.display(row.key), "store_object_id": row.id,
                  "issue": "an ingested evidence-document version has no document"}
                 for row in session.execute(
                     text("SELECT o.id, o.key " + _ORPHAN_OBJECTS + "ORDER BY o.id LIMIT :limit"),
                     {"limit": MAX_REPORTED})]
    session.rollback()
    return {"checked": checked, "failures": failures[:MAX_REPORTED], "failure_count": mismatched + orphaned}


def store_conflicts(session) -> dict:
    """The decision-log exports the store authority refused as conflicts (informational)."""
    count = session.execute(text("SELECT count(*) " + _STORE_CONFLICTS)).scalar() or 0
    items = [{"id": row.id, "bucket": row.bucket, "key": keys.display(row.key), "version_id": row.version_id,
              "detail": row.detail}
             for row in session.execute(text("SELECT o.id, o.bucket, o.key, o.version_id, o.detail " + _STORE_CONFLICTS
                                             + "ORDER BY o.created_at, o.id LIMIT :limit"), {"limit": MAX_REPORTED})]
    session.rollback()
    return {"items": items, "count": count}


# ----------------------------------------------------------------------------
# Listing
# ----------------------------------------------------------------------------

def verify_listing(session, client, bucket: str, *, prefix_index: int = 0, after_key: str | None = None,
                   max_versions: int | None = None) -> dict:
    """Check every listed version under the prefixes from ``prefix_index`` /
    ``after_key`` on (at most about ``max_versions``, stopping between keys).
    A prefix whose listing fails is a failure; the check goes on with the next."""
    from app.services.evidence_store.sync import recorded_versions

    failures, unrecorded, listed = Capped(), Capped(), 0
    resume = None

    def check_batch(batch):
        firsts = [g.first for g in batch if g.first is not None]
        known = recorded_versions(bucket, [v.key for v in firsts])
        session.rollback()
        for group in batch:
            for later in group.later:
                failures.add({"key": keys.display(later.key), "version_id": later.version_id,
                              "issue": SECOND_VERSION})
            for _ in range(group.later_count - len(group.later)):
                failures.add({"key": keys.display(group.key), "version_id": None, "issue": SECOND_VERSION})
            for marker in group.markers:
                failures.add({"key": keys.display(marker.key), "version_id": marker.version_id,
                              "issue": DELETE_MARKER})
            for _ in range(group.marker_count - len(group.markers)):
                failures.add({"key": keys.display(group.key), "version_id": None, "issue": DELETE_MARKER})
            first = group.first
            if first is not None and (first.key, first.version_id) not in known:
                unrecorded.add({"key": keys.display(first.key), "version_id": first.version_id, "size": first.size})

    for index in range(prefix_index, len(PREFIXES)):
        batch, errors = [], []
        start = after_key if index == prefix_index else None
        for group in store.iter_groups_safely(client, bucket, PREFIXES[index], errors, start_after=start):
            batch.append(group)
            listed += (1 if group.first else 0) + group.later_count + group.marker_count
            if len(batch) >= store.LIST_PAGE_SIZE:
                check_batch(batch)
                batch = []
            if max_versions is not None and listed >= max_versions:
                resume = {"prefix": index, "after_key": group.key}
                break
        if batch:
            check_batch(batch)
        for exc in errors:
            failures.add({"key": PREFIXES[index], "version_id": None,
                          "issue": f"the listing cannot be read ({store.describe(exc)})"})
        if resume is not None:
            break
    return {"listed": listed, "failures": failures.report(), "failure_count": failures.count,
            "unrecorded": unrecorded.report(), "unrecorded_count": unrecorded.count, "resume": resume}


def encode_cursor(value: dict | None) -> str | None:
    if value is None:
        return None
    return base64.urlsafe_b64encode(json.dumps(value, sort_keys=True).encode("utf-8")).decode("ascii")


def decode_cursor(cursor: str | None) -> dict:
    """The position a cursor names (``{"phase": "records", "after_id"}`` or
    ``{"phase": "listing", "prefix", "after_key"}``); ValueError when malformed."""
    if not cursor:
        return {"phase": "records", "after_id": None}
    try:
        value = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("cursor is not one this endpoint returned") from exc
    if not isinstance(value, dict) or value.get("phase") not in ("records", "listing"):
        raise ValueError("cursor is not one this endpoint returned")
    if value["phase"] == "listing" and not (isinstance(value.get("prefix"), int)
                                            and 0 <= value["prefix"] < len(PREFIXES)
                                            and isinstance(value.get("after_key"), (str, type(None)))):
        raise ValueError("cursor is not one this endpoint returned")
    if value["phase"] == "records" and not isinstance(value.get("after_id"), (str, type(None))):
        raise ValueError("cursor is not one this endpoint returned")
    return value


def verify_store(session, client, bucket: str, *, full: bool = False, cursor: str | None = None,
                 max_items: int | None = None, workers: int = DEFAULT_WORKERS, max_bytes: int | None = None) -> dict:
    """Verify the bucket, the records, the store's findings, the documents and the
    listing (module docstring).

    Without ``max_items`` / ``max_bytes`` everything is checked in one call;
    with them one slice is checked (at most ``max_items`` records, then
    listed versions, and ``max_bytes`` of bodies read) and ``next_cursor``
    continues the run (``budget_exhausted``: the slice stopped at a budget).
    """
    position = decode_cursor(cursor)
    floors = retention_floors(session)
    bucket_check = check_bucket(client, bucket, floor_days=floors.get(bucket),
                                floor_required=_has_records(session, bucket))
    history = retention_floor_history(session, bucket)
    bucket_check["issues"] += history["issues"] + first_floor_issues(session, client, bucket, history["first_days"])
    bucket_check["retention_floor_lowerings"] = history["lowerings"][:MAX_REPORTED]
    bucket_check["retention_floor_lowerings_count"] = len(history["lowerings"])
    result = {"bucket": bucket, "bucket_check": bucket_check, "full": full, "documents": None,
              "store_findings": None, "store_conflicts": None, "store_conflicts_count": None}
    records = listing = None
    next_position = None
    if position["phase"] == "records":
        if not position.get("after_id"):
            result["documents"] = verify_documents(session)
            result["store_findings"] = verify_store_findings(session)
            conflicts = store_conflicts(session)
            result["store_conflicts"], result["store_conflicts_count"] = conflicts["items"], conflicts["count"]
        records = verify_records(session, client, full=full, after_id=position.get("after_id"),
                                 max_records=max_items, workers=workers, floors=floors, max_bytes=max_bytes)
        if records["next_after_id"] is not None:
            next_position = {"phase": "records", "after_id": records["next_after_id"]}
        elif max_items is not None or max_bytes is not None:
            next_position = {"phase": "listing", "prefix": 0, "after_key": None}
    if position["phase"] == "listing" or (records is not None and next_position is None):
        listing = verify_listing(session, client, bucket, prefix_index=position.get("prefix", 0),
                                 after_key=position.get("after_key"), max_versions=max_items)
        if listing["resume"] is not None:
            next_position = {"phase": "listing", "prefix": listing["resume"]["prefix"],
                             "after_key": listing["resume"]["after_key"]}
    result["records"] = records
    result["listing"] = listing
    failures = len(result["bucket_check"]["issues"]) + (records or {}).get("failure_count", 0) \
        + (listing or {}).get("failure_count", 0) + (result["documents"] or {}).get("failure_count", 0) \
        + (result["store_findings"] or {}).get("failure_count", 0)
    result["bytes_read"] = (records or {}).get("bytes_read", 0)
    result["budget_exhausted"] = bool((records or {}).get("budget_exhausted")) \
        or bool(listing is not None and listing["resume"] is not None)
    unrecorded = (listing or {}).get("unrecorded_count", 0) + (records or {}).get("pending_count", 0)
    result["failure_count"] = failures
    result["unrecorded_count"] = unrecorded
    unverified = unrecorded or result["bucket_check"]["erasure_principals"]
    result["status"] = "broken" if failures else ("unverified" if unverified else "valid")
    result["next_cursor"] = encode_cursor(next_position)
    return result


# ----------------------------------------------------------------------------
# Decision logs against the store
# ----------------------------------------------------------------------------

def _body_fingerprint(client, record: RecordRow) -> dict:
    """The fingerprint (``decision_log_repo_verify.content_fingerprint``) of a
    recorded transcript's body - that exact version, streamed within the
    transcript limit while holding room in the process's transcript import
    budget - or ``{"kind": "unreadable", "error"}``."""
    from app.services.decision_log_repo_verify import content_fingerprint
    from app.services.evidence_import_decision_logs import MAX_TRANSCRIPT_BYTES, import_slot

    try:
        with import_slot(size=record.size):
            content = store.read_version(client, record.bucket, record.s3_key, record.version_id,
                                         MAX_TRANSCRIPT_BYTES)
            return content_fingerprint(content)
    except store.BodyTooLarge as exc:
        return {"kind": "unreadable", "error": f"the body is larger than the transcript limit of {exc.limit} bytes"}
    except Exception as exc:  # noqa: BLE001 - reported per version, never a crash
        return {"kind": "unreadable", "error": f"the body cannot be read ({store.describe(exc)})"}


def _examine(client, record: RecordRow) -> dict:
    """``{"issues"}`` when the object fails in the store, else its body's fingerprint."""
    issues = [issue for issue in check_version(client, record) if issue != RETENTION_EXPIRED]
    return {"issues": issues} if issues else _body_fingerprint(client, record)


def verify_decision_logs_against_store(session, client, *, after_session: str | None = None,
                                       max_sessions: int | None = None, workers: int = DEFAULT_WORKERS) -> dict:
    """Check every store-imported decision-log version (module docstring)."""
    window = session.execute(text(
        "SELECT DISTINCT session_id FROM decision_log_transcripts WHERE store_object_id IS NOT NULL "
        "AND session_id > :after ORDER BY session_id" + (" LIMIT :limit" if max_sessions is not None else "")),
        {"after": after_session or "", "limit": max_sessions}).scalars().all()
    rows = session.execute(text(
        "SELECT t.id AS version_id, t.session_id, t.status AS version_status, t.content_sha256, t.entry_count, "
        "t.entries_sha256, t.store_object_id, o.id, o.bucket, o.key, o.key_escaped, o.version_id AS object_version, "
        "o.kind, o.status, o.sha256, o.size, o.etag, o.last_modified, o.retain_until, o.lock_mode, o.erased_at, "
        "o.composite_checksum "
        "FROM decision_log_transcripts t LEFT JOIN evidence_store_objects o ON o.id = t.store_object_id "
        "WHERE t.store_object_id IS NOT NULL AND t.session_id IN :ids ORDER BY t.session_id, t.received_at, t.id"
    ).bindparams(bindparam("ids", expanding=True)), {"ids": list(window)}).all() if window else []
    session.rollback()  # no snapshot is held while S3 answers
    found = {"mismatches": [], "missing": [], "unreadable": [], "erased": []}
    to_check = {}
    checked_rows = []
    for row in rows:
        item = {"session_id": row.session_id, "version_id": row.version_id, "status": row.version_status,
                "store_object_id": row.store_object_id}
        if row.id is None:
            found["missing"].append(dict(item, issue="the store object the version names is not recorded"))
            continue
        record = to_check.get(row.id) or RecordRow(
            id=row.id, bucket=row.bucket, key=row.key, version_id=row.object_version, kind=row.kind,
            status=row.status, sha256=row.sha256, size=row.size, etag=row.etag, last_modified=row.last_modified,
            retain_until=row.retain_until, lock_mode=row.lock_mode, key_escaped=bool(row.key_escaped),
            composite_checksum=row.composite_checksum)
        item["key"] = keys.display(row.key)
        if row.status == "erased":
            found["erased"].append(dict(item, erased_at=row.erased_at))
        elif row.kind != keys.KIND_DECISION_LOG or _session_of(record) != row.session_id:
            found["mismatches"].append(dict(item, issue="the store object is not a decision log of this session"))
        elif row.sha256 != row.content_sha256:
            found["mismatches"].append(dict(item, issue="the object's recorded SHA-256 differs from the version's"))
        else:
            to_check[row.id] = record
            checked_rows.append((row, item))
    objects = list(to_check.values())
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        examined = dict(zip([o.id for o in objects], pool.map(lambda o: _examine(client, o), objects)))
    for row, item in checked_rows:
        outcome = examined[row.id]
        if outcome.get("issues"):
            issues = outcome["issues"]
            target = found["missing"] if MISSING in issues or IS_DELETE_MARKER in issues else found["mismatches"]
            target.append(dict(item, issue="; ".join(issues)))
        elif "kind" in outcome:
            found["unreadable"].append(dict(item, issue=outcome["error"]))
        else:
            differences = [name for name, ok in (
                ("sha256", outcome["sha256"] == row.sha256 == row.content_sha256),
                ("entries", outcome["entries"] == row.entry_count),
                ("entries_sha256", row.entries_sha256 is None or outcome["entries_sha256"] == row.entries_sha256))
                if not ok]
            if differences:
                found["mismatches"].append(dict(item, issue="the object's body is not this version "
                                                            f"({', '.join(differences)} differ)"))
    status = "broken" if found["mismatches"] or found["missing"] or found["unreadable"] else "valid"
    result = {"status": status, "sessions": len(window), "versions_checked": len(rows),
              "objects_checked": len(objects),
              "next_after_session": window[-1] if max_sessions is not None and len(window) >= max_sessions else None}
    for name, items in found.items():
        result[name] = items[:MAX_REPORTED]
        result[f"{name}_count"] = len(items)
    return result
