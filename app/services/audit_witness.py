"""External witness for the audit chain: published chain heads.

The hash chain proves that ``audit_log`` rows are consistent with each
other; on its own it cannot prove that the newest rows were not removed or
that the whole tail was not rewritten by someone able to write the table
(the database owner). The portal therefore publishes the chain head - the
id and ``row_hash`` of the newest row - to a write-once store outside the
database: an S3 bucket with Object Lock (``AUDIT_WITNESS_BUCKET``). A later
verification compares every published head with the database: a published
row that is missing, or whose ``row_hash`` differs, is evidence of tampering
after the publication.

Arming
------
The witness publishes nothing until it is ARMED: an owner-only, audited
action recorded in ``audit_witness_arming`` (``python -m cli
audit-witness-arm``; ``python -m cli audit-anchor --manifest`` arms it as
part of a cutover). A trial or shakedown database is never armed, so it
never publishes heads that no later chain continues.
``AUDIT_WITNESS_DISABLED=true`` (process environment only, never the runtime
secret) overrides everything: nothing is published. ``/api/health`` reports
``witness``: ``disabled``, ``unconfigured`` (no bucket), ``unarmed`` or
``enabled``, and ``last_published_at``.

Publication
-----------
- Key: ``chain-heads/<chain_id>/<YYYY>/<MM>/<DD>/<YYYYMMDDTHHMMSSZ>-<row id>.json``
  where ``chain_id`` is the first 16 hex characters of the ``row_hash`` of
  the chain's first row (the ANCHOR row of a database that continues an
  archived chain, otherwise the first hashed row).
- Body (``trust-portal-chain-head/v1``, at most 4 KiB): ``chain_id``, ``id``,
  ``row_hash``, ``hash_version``, ``published_at``, ``database``, ``anchor``
  (the anchor's archive reference and manifest key, or null) and
  ``portal_version``.
- One ``PutObject`` per publication with ``If-None-Match: *`` (an existing
  object is never replaced; the bucket policy also denies writes without it)
  and a SHA-256 checksum; retention comes from the bucket's default Object
  Lock configuration. When the key already exists, the stored object is read
  back: identical means already published; anything else is a CONFLICT
  (logged as ``audit_witness_conflict``) and the head is published again
  under the next second's key. The runtime role writes only
  ``chain-heads/*``; it never writes ``archives/``. The database read ends
  before the S3 call, which uses short timeouts and bounded retries. Every
  publication that reached S3 is recorded in ``audit_witness_publications``.
- The scheduler leader publishes when it gains leadership and then hourly
  when the head has changed; ``python -m cli audit-anchor``,
  ``audit-witness-arm`` and ``audit-publish-head`` publish immediately, and
  ``audit-archive-manifest`` publishes the archived chain's final head. When
  the witness is enabled and armed, the head has moved and nothing was
  published for more than two hours, the leader logs ``audit_witness_stale``
  every hour and the admin dashboard shows a warning.

Verification
------------
``load_heads_s3`` reads EVERY object version under ``chain-heads/``
(``s3:ListBucketVersions`` and ``s3:GetObjectVersion``); ``load_heads_file``
reads a downloaded copy (a directory mirroring the keys, or a JSON array /
JSON lines of ``{"key", "head"}`` items). The object KEY is authoritative:
heads are grouped by the chain id in the key, and a head whose body
disagrees with its key (chain id or row id), an object over 4 KiB, a
non-JSON or schema-invalid body, an object that cannot be read (any S3
error, including KMS or SSE-C encryption) and any key not of the head form
are INVALID WITNESS OBJECTS: each is reported with its key, and the result
is broken. ``check_heads`` and ``resolve_foreign_chains`` then decide:

- every published head of the CURRENT chain must match the database row with
  the same id (missing or different = mismatch);
- a published chain other than the current one is acceptable only when a
  VERIFIED archive manifest of the current chain's anchor lineage
  (``app.services.audit_archive``) names that chain id and that chain's
  last published head (row id and ``row_hash``) as its final row; without
  access to the manifests (the anchor is unverified) a chain the anchor
  names is an unverified continuation, and the result is ``unverified``;
  any other foreign chain is a mismatch - the audit log was replaced;
- when heads were published but none belongs to the current chain, the
  result is a failure, never "valid".

What this proves: every row that existed when a head was published is still
present and unchanged, and the current chain descends from every chain ever
published to the bucket, through anchors whose archive manifests were
written under Object Lock with operator credentials. It does not prove
anything about rows written after the last publication (at most an hour, or
since the last anchor); the rows of an archived chain are in its archive
(``python -m cli audit-verify --witness-s3 --rehash-archive`` recomputes the
archive's SHA-256), not in this database.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

logger = logging.getLogger(__name__)

FORMAT = "trust-portal-chain-head/v1"
PREFIX = "chain-heads/"
PUBLISH_INTERVAL_SECONDS = 3600
STALE_AFTER_SECONDS = 2 * 3600
MAX_HEAD_BYTES = 4096
MAX_REPORTED = 100
CONFLICT_RETRIES = 3
HEAD_KEY = re.compile(r"^chain-heads/([0-9a-f]{16})/(\d{4})/(\d{2})/(\d{2})/(\d{8}T\d{6}Z)-([1-9]\d{0,18})\.json$")
HEX16 = re.compile(r"^[0-9a-f]{16}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class WitnessError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# State: configured, armed, last publication
# --------------------------------------------------------------------------

def witness_bucket() -> str | None:
    """The bucket heads are published to; None when publishing is disabled
    (``AUDIT_WITNESS_DISABLED``) or not configured."""
    from app.runtime_config import env, witness_disabled

    if witness_disabled():
        return None
    return env("AUDIT_WITNESS_BUCKET")


_armed_cache: set[str] = set()


def _table_exists(session, name: str) -> bool:
    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        from sqlalchemy import inspect

        return inspect(bind).has_table(name)
    return session.execute(text("SELECT to_regclass(:n) IS NOT NULL"), {"n": f"public.{name}"}).scalar()


def is_armed(session) -> bool:
    """True once ``audit_witness_arm`` has run on this database (append-only, so cached)."""
    database = str(session.get_bind().url)
    if database in _armed_cache:
        return True
    if not _table_exists(session, "audit_witness_arming"):
        return False
    armed = session.execute(text("SELECT EXISTS (SELECT 1 FROM audit_witness_arming)")).scalar()
    if armed:
        _armed_cache.add(database)
    return bool(armed)


def last_publication(session) -> dict | None:
    if not _table_exists(session, "audit_witness_publications"):
        return None
    row = session.execute(text(
        "SELECT published_at, head_id, object_key, outcome FROM audit_witness_publications "
        "ORDER BY published_at DESC, id DESC LIMIT 1")).mappings().first()
    return dict(row) if row else None


def witness_state(session=None) -> str:
    """``disabled`` (AUDIT_WITNESS_DISABLED), ``unconfigured`` (no bucket),
    ``unarmed`` (bucket set, not armed) or ``enabled``. Without a session the
    arming is not checked (``enabled`` means a bucket is set)."""
    from app.runtime_config import env, witness_disabled

    if witness_disabled():
        return "disabled"
    if not env("AUDIT_WITNESS_BUCKET"):
        return "unconfigured"
    if session is not None and not is_armed(session):
        return "unarmed"
    return "enabled"


def _as_utc(value):
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def witness_status(session=None) -> dict:
    """State, last publication and staleness (for /api/health and the admin dashboard)."""
    if session is None:
        from app.models import db

        session = db.session
    state = witness_state(session)
    last = last_publication(session) if state != "unconfigured" else None
    head = _head_id(session) if state == "enabled" else None
    published_at = _as_utc(last["published_at"]) if last else None
    stale = False
    if state == "enabled" and head is not None and (last is None or head > last["head_id"]):
        reference = published_at or _armed_at(session)
        stale = reference is not None and \
            datetime.now(timezone.utc) - reference > timedelta(seconds=STALE_AFTER_SECONDS)
    return {"state": state,
            "last_published_at": published_at.strftime("%Y-%m-%dT%H:%M:%SZ") if published_at else None,
            "last_published_id": last["head_id"] if last else None,
            "head_id": head, "stale": stale}


def witness_status_for_display() -> dict:
    """``witness_status`` for templates: never raises (a failure shows no warning)."""
    from app.models import db

    try:
        return witness_status(db.session)
    except Exception:  # noqa: BLE001 - the page renders without the witness banner
        db.session.rollback()
        logger.exception("Could not read the audit witness status")
        return {"state": witness_state(), "last_published_at": None, "last_published_id": None,
                "head_id": None, "stale": False}


def _head_id(session) -> int | None:
    return session.execute(text("SELECT max(id) FROM audit_log WHERE row_hash IS NOT NULL")).scalar()


def _armed_at(session):
    if not _table_exists(session, "audit_witness_arming"):
        return None
    return _as_utc(session.execute(text("SELECT min(armed_at) FROM audit_witness_arming")).scalar())


def arm(session, note: str | None = None) -> int:
    """Arm the witness (owner role only: ``audit_witness_arm`` is not executable by the app role)."""
    return int(session.execute(text("SELECT audit_witness_arm(:note)"), {"note": note}).scalar())


# --------------------------------------------------------------------------
# Publishing
# --------------------------------------------------------------------------

def chain_id(session) -> str | None:
    """First 16 hex chars of the chain's first row_hash (anchor or first hashed row)."""
    first = session.execute(text(
        "SELECT row_hash FROM audit_log WHERE row_hash IS NOT NULL ORDER BY id LIMIT 1")).scalar()
    return first[:16] if first else None


def current_head(session) -> dict | None:
    """The head record to publish, or None for an empty/unhashed chain."""
    cid = chain_id(session)
    if cid is None:
        return None
    has_version = session.execute(text(
        "SELECT 1 FROM information_schema.columns WHERE table_name = 'audit_log' "
        "AND column_name = 'hash_version' AND table_schema = current_schema()")).first()
    version_sql = "hash_version" if has_version else "NULL::smallint AS hash_version"
    row = session.execute(text(
        f"SELECT id, row_hash, {version_sql} FROM audit_log "
        "WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1")).mappings().first()
    anchor = session.execute(text(
        "SELECT new_values::text AS details FROM audit_log WHERE action = 'ANCHOR' ORDER BY id LIMIT 1"
    )).scalar()
    from flask import current_app, has_app_context

    return {
        "format": FORMAT,
        "chain_id": cid,
        "id": int(row["id"]),
        "row_hash": row["row_hash"],
        "hash_version": row["hash_version"],
        "published_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "database": session.execute(text("SELECT current_database()")).scalar(),
        "anchor": json.loads(anchor) if anchor else None,
        "portal_version": current_app.config.get("PORTAL_VERSION") if has_app_context() else None,
    }


def s3_client():
    """S3 client with short timeouts and bounded retries (never blocks the leader for long)."""
    from botocore.config import Config

    from app.services.aws_session import get_session

    return get_session().client("s3", config=Config(
        connect_timeout=5, read_timeout=15, retries={"max_attempts": 3, "mode": "standard"}))


def object_key(head: dict) -> str:
    stamp = datetime.strptime(head["published_at"], "%Y-%m-%dT%H:%M:%SZ")
    return (f"{PREFIX}{head['chain_id']}/{stamp:%Y}/{stamp:%m}/{stamp:%d}/"
            f"{stamp:%Y%m%dT%H%M%SZ}-{head['id']}.json")


def _body(head: dict) -> bytes:
    return json.dumps(head, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _error_code(exc) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


def _put_once(client, bucket: str, key: str, body: bytes) -> str:
    """``published``, ``already`` (identical object exists) or ``conflict`` (another object exists)."""
    try:
        client.put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/json",
                          ChecksumAlgorithm="SHA256", IfNoneMatch="*", ServerSideEncryption="AES256")
        return "published"
    except Exception as exc:  # noqa: BLE001 - classified below
        if _error_code(exc) not in ("PreconditionFailed", "412"):
            raise
    try:
        existing = client.get_object(Bucket=bucket, Key=key)["Body"].read(MAX_HEAD_BYTES + 1)
    except Exception:  # noqa: BLE001 - an unreadable object at our key is a conflict
        existing = None
    return "already" if existing == body else "conflict"


def _record(session, head: dict, key: str, outcome: str) -> None:
    try:
        if not _table_exists(session, "audit_witness_publications"):
            return
        session.execute(text(
            "INSERT INTO audit_witness_publications (published_at, head_id, row_hash, object_key, outcome) "
            "VALUES (:at, :id, :h, :k, :o)"),
            {"at": datetime.strptime(head["published_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc),
             "id": head["id"], "h": head["row_hash"], "k": key, "o": outcome})
        session.commit()
    except Exception:  # noqa: BLE001 - the publication itself succeeded
        session.rollback()
        logger.exception("Could not record the audit witness publication of %s", key)


def publish_head(session, *, bucket: str | None = None, client=None, head: dict | None = None,
                 require_armed: bool = True) -> dict | None:
    """Publish the current chain head (or ``head``, one read earlier by
    ``current_head``). Returns ``{"key", "head", "outcome"}`` or None when the
    witness is disabled, unconfigured or unarmed, or there is nothing to
    publish. ``require_armed=False`` is for ``audit-archive-manifest``, which
    publishes an archived chain's final head on an explicit operator command."""
    from app.runtime_config import witness_disabled

    if witness_disabled():
        logger.info("Audit chain head not published: AUDIT_WITNESS_DISABLED is set")
        return None
    bucket = bucket or witness_bucket()
    if not bucket:
        return None
    if require_armed and not is_armed(session):
        logger.info("Audit chain head not published: the witness is not armed (python -m cli audit-witness-arm)")
        return None
    head = dict(head) if head else current_head(session)
    if head is None:
        return None
    if client is None:
        client = s3_client()
    # End the read transaction before the network call: no audit_log snapshot
    # or lock is held while S3 answers.
    session.rollback()
    conflicts = []
    for _ in range(CONFLICT_RETRIES + 1):
        key = object_key(head)
        outcome = _put_once(client, bucket, key, _body(head))
        if outcome != "conflict":
            break
        conflicts.append(key)
        logger.error("audit_witness_conflict key=%s head_id=%s: a different object already exists at the "
                     "head's key; publishing under the next second's key", key, head["id"])
        stamp = datetime.strptime(head["published_at"], "%Y-%m-%dT%H:%M:%SZ") + timedelta(seconds=1)
        head["published_at"] = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        raise WitnessError(f"could not publish head {head['id']}: every key conflicted ({', '.join(conflicts)})")
    if require_armed:
        _record(session, head, key, "conflict" if conflicts else outcome)
    if outcome == "already":
        logger.info("Audit chain head %s already published at %s", head["id"], key)
    else:
        logger.info("Published audit chain head %s (row %s) to s3://%s/%s",
                    head["row_hash"][:16], head["id"], bucket, key)
    return {"key": key, "head": head, "outcome": outcome, "conflicts": conflicts,
            "sha256": hashlib.sha256(_body(head)).hexdigest(), "already_published": outcome == "already"}


class PeriodicPublisher:
    """Publishes on gaining leadership and then when the head changed; logs a stale witness."""

    def __init__(self):
        self.last_published_id: int | None = None

    def __call__(self, app) -> dict | None:
        from app.models import db

        if not witness_bucket() or not is_armed(db.session):
            return None
        if self.last_published_id is None:
            last = last_publication(db.session)
            self.last_published_id = last["head_id"] if last else None
        head = current_head(db.session)
        result = None
        if head is not None and head["id"] != self.last_published_id:
            try:
                result = publish_head(db.session, head=head)
            except Exception:  # noqa: BLE001 - logged; staleness is reported below
                logger.exception("Audit chain head publication failed")
            if result:
                self.last_published_id = result["head"]["id"]
        status = witness_status(db.session)
        db.session.rollback()
        if status["stale"]:
            logger.warning("audit_witness_stale last_published_at=%s last_published_id=%s head_id=%s: no "
                           "chain head published for more than %s hours while the head moved",
                           status["last_published_at"], status["last_published_id"], status["head_id"],
                           STALE_AFTER_SECONDS // 3600)
        return result


def register() -> None:
    """Register hourly chain-head publishing with the scheduler leader."""
    from app.services.scheduler import register_periodic

    register_periodic("audit_witness", PUBLISH_INTERVAL_SECONDS, PeriodicPublisher())


# --------------------------------------------------------------------------
# Reading heads: the key is authoritative
# --------------------------------------------------------------------------

def key_parts(key: str) -> tuple[str, int] | None:
    """(chain id, row id) from a head object key, or None when the key is not of the head form."""
    match = HEAD_KEY.match(key or "")
    return (match.group(1), int(match.group(6))) if match else None


def parse_head(key: str, body) -> tuple[dict | None, str | None]:
    """(head, None) for a valid head object at ``key``, else (None, reason).

    ``body`` is the object's bytes (or an already-parsed object from a
    downloaded list). The key must be of the head form, the body at most
    4 KiB of JSON with ``format``, ``chain_id``, ``id`` and ``row_hash`` of the
    right shape, and the body's chain id and row id must equal the key's.
    """
    parts = key_parts(key)
    if parts is None:
        return None, "key is not chain-heads/<chain id>/YYYY/MM/DD/<timestamp>-<row id>.json"
    if isinstance(body, (bytes, bytearray)):
        if len(body) > MAX_HEAD_BYTES:
            return None, f"object larger than {MAX_HEAD_BYTES} bytes"
        try:
            head = json.loads(body)
        except ValueError:
            return None, "not JSON"
    else:
        head = body
        if len(json.dumps(head, default=str)) > MAX_HEAD_BYTES:
            return None, f"object larger than {MAX_HEAD_BYTES} bytes"
    if not isinstance(head, dict):
        return None, "not a JSON object"
    if head.get("format") != FORMAT:
        return None, f"format is not {FORMAT}"
    row_id = head.get("id")
    if not isinstance(head.get("chain_id"), str) or not HEX16.match(head["chain_id"]) \
            or not isinstance(row_id, int) or isinstance(row_id, bool) or row_id < 1 \
            or not isinstance(head.get("row_hash"), str) or not HEX64.match(head["row_hash"]):
        return None, "chain_id, id or row_hash missing or malformed"
    if (head["chain_id"], row_id) != parts:
        return None, "body disagrees with its key (chain id or row id)"
    return head, None


def empty_scan() -> dict:
    return {"valid": [], "invalid": []}


def scan_heads(client, bucket: str, prefix: str = PREFIX) -> dict:
    """Every object version under ``prefix``: ``{"valid": [{"key", "version_id", "head"}],
    "invalid": [{"key", "version_id", "reason"}]}``. A listing failure raises;
    an object that cannot be read or parsed is an invalid entry, never an exception."""
    scan = empty_scan()
    paginator = client.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for item in page.get("Versions", []):
            version = item.get("VersionId")
            version = None if version in (None, "null") else version
            entry = {"key": item["Key"], "version_id": version}
            if key_parts(item["Key"]) is None:
                scan["invalid"].append(dict(entry, reason="key is not of the chain head form"))
                continue
            if item.get("Size", 0) > MAX_HEAD_BYTES:
                scan["invalid"].append(dict(entry, reason=f"object larger than {MAX_HEAD_BYTES} bytes"))
                continue
            kwargs = {"Bucket": bucket, "Key": item["Key"]}
            if version:
                kwargs["VersionId"] = version
            try:
                body = client.get_object(**kwargs)["Body"].read(MAX_HEAD_BYTES + 1)
            except Exception as exc:  # noqa: BLE001 - any read failure (KMS, SSE-C, ...) is reported
                code = _error_code(exc) or exc.__class__.__name__
                scan["invalid"].append(dict(entry, reason=f"unreadable ({code})"))
                continue
            head, reason = parse_head(item["Key"], body)
            if head is None:
                scan["invalid"].append(dict(entry, reason=reason))
            else:
                scan["valid"].append(dict(entry, head=head))
    return scan


def load_heads_s3(bucket: str, chain: str | None = None, client=None) -> dict:
    """Every published head: all chains (or one, when ``chain`` is given) and
    every object version, so an overwritten or delete-marked head still counts."""
    if client is None:
        client = s3_client()
    return scan_heads(client, bucket, PREFIX + (f"{chain}/" if chain else ""))


def heads_from_items(items, *, strict: bool) -> dict:
    """Heads from downloaded ``{"key", "head"}`` items (a file, or the verify API).

    With ``strict`` any invalid item raises WitnessError (the API answers
    400); otherwise invalid items are reported like invalid objects.
    """
    if not isinstance(items, list):
        raise WitnessError("heads must be a list of {\"key\", \"head\"} items")
    scan = empty_scan()
    for index, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("key"), str) or "head" not in item:
            raise WitnessError(f"heads[{index}] is not a {{\"key\", \"head\"}} item")
        head, reason = parse_head(item["key"], item["head"])
        if head is None:
            if strict:
                raise WitnessError(f"heads[{index}] ({item['key'][:200]}): {reason}")
            scan["invalid"].append({"key": item["key"], "version_id": None, "reason": reason})
        else:
            scan["valid"].append({"key": item["key"], "version_id": None, "head": head})
    return scan


def load_heads_file(path: str) -> dict:
    """Heads from a downloaded copy: a directory mirroring the object keys (as
    ``aws s3 sync s3://<bucket>/chain-heads <dir>`` or ``.../<bucket> <dir>``
    writes it), or a JSON array / JSON lines of ``{"key", "head"}`` items."""
    if os.path.isdir(path):
        scan = empty_scan()
        for root, _, files in os.walk(path):
            for name in sorted(files):
                full = os.path.join(root, name)
                rel = os.path.relpath(full, path).replace(os.sep, "/")
                key = rel if rel.startswith(PREFIX) else PREFIX + rel
                with open(full, "rb") as handle:
                    body = handle.read(MAX_HEAD_BYTES + 1)
                head, reason = parse_head(key, body)
                if head is None:
                    scan["invalid"].append({"key": key, "version_id": None, "reason": reason})
                else:
                    scan["valid"].append({"key": key, "version_id": None, "head": head})
        return scan
    with open(path, encoding="utf-8") as handle:
        raw = handle.read().strip()
    if not raw:
        return empty_scan()
    try:
        if raw.startswith("["):
            items = json.loads(raw)
        else:
            items = [json.loads(line) for line in raw.splitlines() if line.strip()]
    except ValueError as exc:
        raise WitnessError(f"{path} is not a JSON array or JSON lines: {exc}") from exc
    return heads_from_items(items, strict=False)


# --------------------------------------------------------------------------
# Checking heads against the database
# --------------------------------------------------------------------------

MAX_LOOKUP_BATCH = 1000


def _mismatch(row_id, cid, published, stored, published_at, issue, key=None):
    return {"id": row_id, "chain_id": cid, "published_row_hash": published, "stored_row_hash": stored,
            "published_at": published_at, "key": key, "issue": issue}


def check_heads(session, scan: dict) -> dict:
    """Compare the current chain's published heads with the database and list
    the foreign chains (decided later by ``resolve_foreign_chains``)."""
    ours = chain_id(session)
    by_chain: dict[str, list[dict]] = {}
    for entry in scan["valid"]:
        by_chain.setdefault(key_parts(entry["key"])[0], []).append(entry)

    mismatches, checked = [], 0
    current = by_chain.pop(ours, []) if ours else []
    ids = sorted({e["head"]["id"] for e in current})
    stored: dict[int, str] = {}
    for start in range(0, len(ids), MAX_LOOKUP_BATCH):
        for row in session.execute(text("SELECT id, row_hash FROM audit_log WHERE id = ANY(:ids)"),
                                   {"ids": ids[start:start + MAX_LOOKUP_BATCH]}).all():
            stored[row.id] = row.row_hash
    for entry in current:
        head = entry["head"]
        checked += 1
        row_hash = stored.get(head["id"])
        if row_hash != head["row_hash"]:
            mismatches.append(_mismatch(head["id"], ours, head["row_hash"], row_hash, head.get("published_at"),
                                        "row missing" if row_hash is None else "row_hash differs", entry["key"]))

    foreign = []
    for cid, entries in sorted(by_chain.items()):
        last = max(entries, key=lambda e: e["head"]["id"])
        foreign.append({"chain_id": cid, "last_published_id": last["head"]["id"],
                        "last_published_row_hash": last["head"]["row_hash"],
                        "last_published_at": last["head"].get("published_at"), "key": last["key"],
                        "heads": len(entries)})
    if (scan["valid"] or scan["invalid"]) and checked == 0:
        mismatches.append(_mismatch(None, ours, None, None, None,
                                    "heads were published but none belongs to the current chain"))
    latest = max((e["head"]["id"] for e in current), default=None)
    return {"checked": checked, "published": len(scan["valid"]) + len(scan["invalid"]),
            "foreign_chains": foreign, "continued_chains": [], "unverified_continuations": [],
            "other_chain": sum(f["heads"] for f in foreign), "mismatches": mismatches,
            "invalid_heads": scan["invalid"], "latest_published_id": latest}


def resolve_foreign_chains(witness: dict, anchor: dict | None, anchor_verification: dict | None) -> dict:
    """Accept a foreign chain only through a verified manifest (module docstring)."""
    lineage = {(m["chain_id"], m["final_row_id"], m["final_row_hash"])
               for m in (anchor_verification or {}).get("lineage") or []}
    unverified_anchor = bool(anchor) and (anchor_verification or {}).get("status") == "unverified"
    for chain in witness.pop("foreign_chains", []):
        signature = (chain["chain_id"], chain["last_published_id"], chain["last_published_row_hash"])
        if signature in lineage:
            witness["continued_chains"].append(chain)
        elif unverified_anchor and anchor.get("archived_chain_head") == chain["last_published_row_hash"]:
            witness["unverified_continuations"].append(chain)
        else:
            witness["mismatches"].append(_mismatch(
                None, chain["chain_id"], chain["last_published_row_hash"], None, chain["last_published_at"],
                "a published chain that no verified archive manifest of the current chain continues at its "
                "last published head: the audit log was replaced", chain["key"]))
    return witness


def report(witness: dict) -> dict:
    """The witness block of a verification result, long lists truncated with counts."""
    out = dict(witness)
    for field in ("mismatches", "invalid_heads", "continued_chains", "unverified_continuations"):
        items = witness.get(field) or []
        out[field] = items[:MAX_REPORTED]
        out[f"{field}_count"] = len(items)
    return out
