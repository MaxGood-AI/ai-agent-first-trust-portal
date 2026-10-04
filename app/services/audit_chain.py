"""Audit-log hash chain: verification, anchors and read-side redaction.

Chain rules (enforced by ``audit_trigger_func()``, migration 016):

- Every audited change appends one ``audit_log`` row whose ``previous_hash``
  is the ``row_hash`` of the row before it (by ``id``) and whose ``row_hash``
  is ``sha256(previous_hash || table_name || record_id || action ||
  [changed_by || changed_at] || old_values::text || new_values::text)``.
  The bracketed part is present for ``hash_version = 2`` rows; rows written
  by migration 014's trigger (``hash_version`` NULL) use the formula without it.
- A chain starts at genesis (``previous_hash`` = 64 zeros), or at an ANCHOR
  row: the first row of a database whose earlier chain was archived. The
  anchor's ``previous_hash`` is the archived chain's final ``row_hash`` and its
  ``new_values`` record the archive id and SHA-256 and the key and SHA-256 of
  the archive manifest in the witness bucket. An anchor is never taken on its
  own word: ``verify_chain`` reports ``unverified`` unless the anchor is
  checked against its manifest (``anchor_verifier``,
  ``app.services.audit_archive.verify_anchor``), and ``broken`` when that
  check fails.
- Rows written before migration 014 carry no hashes; they precede the chain
  and are reported as ``unhashed_entries``.

``verify_chain`` recomputes every hash inside PostgreSQL, in id-ordered
chunks, so it runs in bounded memory on a table of any size; it can stop
after ``max_rows`` and be resumed from ``next_after_id`` with
``expected_previous_hash``. It reports three kinds of finding separately:
content mismatches (a row altered after it was written), forks (a row linked
to an earlier row other than its predecessor - two writers read the same
chain head, which the unserialized trigger of migration 014 allowed; content
intact, order diverged) and true breaks (a link to no earlier row).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import text

GENESIS_HASH = "0" * 64
MAX_DETAILED_FINDINGS = 1_000
FORK_REASON = ("Forks are rows written before the first serialized (hash_version 2) row: the "
               "earlier, unserialized trigger let concurrent writers read the same chain head. "
               "Their content hashes are intact; only their order diverged.")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Keys that must never be shown from audit rows written before secrets were
# digested (migration 016). Values already in "sha256:<hex>" form are kept.
SENSITIVE_KEYS = {"api_key", "api_key_hash", "encrypted_credentials"}

_V2_PART = """
    || CASE WHEN hash_version = 2
            THEN COALESCE(changed_by, '')
                 || to_char(changed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
            ELSE '' END"""


def _chunk_sql(with_hash_version: bool):
    """Chunk query recomputing each row's hash. A database from before
    migration 016 (e.g. a restored archive) has no ``hash_version`` column;
    every row there uses the v1 formula."""
    expected = f"""
encode(sha256(convert_to(
    COALESCE(previous_hash, '') || table_name || record_id || action{_V2_PART if with_hash_version else ''}
    || COALESCE(old_values::text, '') || COALESCE(new_values::text, ''),
    'UTF8')), 'hex')"""
    return text(f"""
SELECT id, previous_hash, row_hash, action, {expected} AS computed
FROM audit_log
WHERE id > :after_id
ORDER BY id
LIMIT :limit
""")


def _has_hash_version(session) -> bool:
    return bool(session.execute(text(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name = 'audit_log' AND column_name = 'hash_version' "
        "AND table_schema = current_schema()")).first())


AUDIT_CHAIN_LOCK_KEY = 815000001


class AuditChainError(RuntimeError):
    pass


def lock_audit_chain(session) -> None:
    """Take the audit chain's transaction-scoped lock now.

    Every audited write takes it before its first row lock (statement-level
    trigger). Code that row-locks audited rows by other means - ``SELECT ...
    FOR UPDATE`` / ``with_for_update()`` - calls this first, so it follows the
    same lock order (chain lock, then row locks) and cannot deadlock with an
    audited writer. No-op outside PostgreSQL.
    """
    if session.get_bind().dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": AUDIT_CHAIN_LOCK_KEY})


def redact_values(values):
    """Hide secret-bearing keys in audit values written before digesting existed."""
    if not isinstance(values, dict):
        return values
    redacted = {}
    for key, value in values.items():
        if key in SENSITIVE_KEYS and not (isinstance(value, str) and value.startswith("sha256:")) \
                and value is not None:
            redacted[key] = "[redacted]"
        else:
            redacted[key] = value
    return redacted


def _is_postgres(session) -> bool:
    return session.get_bind().dialect.name == "postgresql"


@dataclass
class ChainStart:
    after_id: int
    expected_previous_hash: str
    anchor: dict | None
    unhashed_entries: int


def find_chain_start(session) -> ChainStart | None:
    """Locate where verification begins: an anchor row, or the first hashed row."""
    first = session.execute(text(
        "SELECT id, action, previous_hash, row_hash, new_values::text AS new_values_text, changed_at "
        "FROM audit_log ORDER BY id LIMIT 1"
    )).mappings().first()
    if first is None:
        return None
    if first["action"] == "ANCHOR":
        import json

        details = json.loads(first["new_values_text"] or "{}")
        return ChainStart(
            after_id=first["id"] - 1,
            expected_previous_hash=first["previous_hash"],
            anchor={
                "id": first["id"],
                "archive_id": details.get("archive_id"),
                "archive_sha256": details.get("archive_sha256"),
                "archived_chain_head": first["previous_hash"],
                "archived_entries": details.get("archived_entries"),
                "archive_manifest_key": details.get("archive_manifest_key"),
                "archive_manifest_sha256": details.get("archive_manifest_sha256"),
                "anchored_by": details.get("anchored_by"),
                "note": details.get("note"),
                "anchored_at": first["changed_at"].isoformat() if first["changed_at"] else None,
            },
            unhashed_entries=0,
        )
    first_hashed = session.execute(text(
        "SELECT id FROM audit_log WHERE row_hash IS NOT NULL ORDER BY id LIMIT 1"
    )).scalar()
    if first_hashed is None:
        return ChainStart(after_id=0, expected_previous_hash=GENESIS_HASH, anchor=None,
                          unhashed_entries=-1)
    unhashed = session.execute(text(
        "SELECT count(*) FROM audit_log WHERE id < :first"), {"first": first_hashed}).scalar()
    return ChainStart(after_id=first_hashed - 1, expected_previous_hash=GENESIS_HASH, anchor=None,
                      unhashed_entries=int(unhashed))


def estimated_total(session) -> int:
    estimate = session.execute(text(  # the audit_log the search_path resolves (a scratch copy too)
        "SELECT reltuples::bigint FROM pg_class WHERE oid = to_regclass('audit_log')")).scalar() or 0
    if estimate < 1_000_000:
        return int(session.execute(text("SELECT count(*) FROM audit_log")).scalar())
    return int(estimate)


def _chain_roots(session) -> set[str]:
    """Values a first link may legitimately point at: genesis, and the
    archived chain head recorded by an ANCHOR row."""
    roots = {GENESIS_HASH}
    first = session.execute(text(
        "SELECT action, previous_hash FROM audit_log ORDER BY id LIMIT 1")).first()
    if first is not None and first.action == "ANCHOR" and first.previous_hash:
        roots.add(first.previous_hash)
    return roots


def _earliest_ids(session, hashes: list[str], batch: int = 5_000) -> dict[str, int]:
    """{row_hash: smallest id holding it} for ``hashes`` (one table scan per batch)."""
    found: dict[str, int] = {}
    for start in range(0, len(hashes), batch):
        rows = session.execute(text(
            "SELECT row_hash, min(id) AS first_id FROM audit_log "
            "WHERE row_hash = ANY(:hashes) GROUP BY row_hash"),
            {"hashes": hashes[start:start + batch]}).all()
        for row in rows:
            found[row.row_hash] = row.first_id
    return found


def first_serialized_id(session) -> int | None:
    """Id of the first row written by the serialized (v2) trigger, if any."""
    if not _has_hash_version(session):
        return None
    return session.execute(text("SELECT min(id) FROM audit_log WHERE hash_version = 2")).scalar()


def classify_links(session, candidates: list[tuple[int, str | None]], roots: set[str],
                   serialized_from: int | None = None):
    """Split rows whose ``previous_hash`` is not their predecessor's ``row_hash``.

    A *fork* points at genesis, at the anchored archive head, or at the
    ``row_hash`` of an earlier row other than its immediate predecessor: two
    writes read the same chain head (the race of the unserialized trigger
    before migration 016). The content is intact; only the order diverged.
    A *true break* points at no earlier row at all (or has no hash). From the
    first ``hash_version = 2`` row on (``serialized_from``) writes are
    serialized, so a mislinked row there is always a true break.
    Returns ``(fork_ids, true_break_ids)``.
    """
    lookup = sorted({prev for _, prev in candidates if prev and prev not in roots})
    earliest = _earliest_ids(session, lookup) if lookup else {}
    forks, true_breaks = [], []
    for row_id, prev in candidates:
        serialized = serialized_from is not None and row_id > serialized_from
        if not serialized and prev and (prev in roots or earliest.get(prev, row_id) < row_id):
            forks.append(row_id)
        else:
            true_breaks.append(row_id)
    return forks, true_breaks


def verify_chain(session, *, after_id: int | None = None, expected_previous_hash: str | None = None,
                 max_rows: int | None = None, chunk_size: int = 20_000, progress=None,
                 witness_heads: list[dict] | None = None, anchor_verifier=None) -> dict:
    """Recompute every hash and check every link. See the module docstring.

    Findings are reported separately:

    - ``content_mismatches``: rows whose recomputed hash differs from
      ``row_hash`` (the row was altered after it was written);
    - ``forks``: rows linked to an earlier row other than their predecessor
      (or to genesis / the anchored head); content intact, order diverged;
    - ``true_breaks``: rows linked to no earlier row, or without a hash (and
      any mislinked row after the first serialized ``hash_version = 2`` row);
    - ``witness_mismatches`` (when ``witness_heads`` are given): published
      chain heads (``app.services.audit_witness``) whose row is missing or
      carries a different ``row_hash`` - rows were removed or rewritten;
    - ``anchor_verification`` (a chain that starts with an ANCHOR row): the
      result of ``anchor_verifier(anchor)`` (``verified``, ``failed`` or
      ``unverified``), or ``unverified`` when no verifier is given. The
      session's read transaction ends before the verifier runs (it reads S3).

    ``status`` is ``valid`` (no findings), ``intact_with_forks`` (forks only),
    ``unverified`` (no findings, but the anchor was not checked against its
    archive manifest) or ``broken`` (any content mismatch, true break, witness
    mismatch or failed anchor).
    """
    if not _is_postgres(session):
        return {"status": "unsupported", "message": "Chain verification requires PostgreSQL."}

    anchor = None
    unhashed = 0
    if after_id is None:
        start = find_chain_start(session)
        if start is None:
            return {"status": "empty", "total_entries": 0, "verified": 0, "chain_head": None,
                    "first_break": None, "breaks": 0, "content_mismatches": 0, "forks": 0,
                    "true_breaks": 0, "anchor": None, "complete": True}
        if start.unhashed_entries == -1:
            return {"status": "no_hashes", "total_entries": estimated_total(session), "verified": 0,
                    "chain_head": None, "first_break": None, "breaks": 0, "content_mismatches": 0,
                    "forks": 0, "true_breaks": 0, "anchor": None, "complete": True,
                    "message": "No hash chain data found. Entries predate the hash chain migration."}
        after_id = start.after_id
        expected = start.expected_previous_hash
        anchor = start.anchor
        unhashed = start.unhashed_entries
    else:
        if not expected_previous_hash or not HEX64.match(expected_previous_hash):
            raise AuditChainError("expected_previous_hash (64 hex chars) is required with after_id")
        expected = expected_previous_hash
        start = find_chain_start(session)
        anchor = start.anchor if start else None  # every slice reports the anchor's standing

    chunk_sql = _chunk_sql(_has_hash_version(session))
    verified = 0
    content_mismatch_ids: list[int] = []
    link_candidates: list[tuple[int, str | None]] = []
    first_details: dict[int, dict] = {}
    last_id = after_id
    chain_head = None
    complete = True

    while True:
        limit = chunk_size
        if max_rows is not None:
            remaining = max_rows - verified
            if remaining <= 0:
                more = session.execute(text("SELECT 1 FROM audit_log WHERE id > :id LIMIT 1"),
                                       {"id": last_id}).first()
                complete = more is None
                break
            limit = min(limit, remaining)
        rows = session.execute(chunk_sql, {"after_id": last_id, "limit": limit}).all()
        if not rows:
            break
        for row in rows:
            linked = row.row_hash is not None and row.previous_hash == expected
            altered = row.row_hash is not None and row.computed != row.row_hash
            if not linked:
                link_candidates.append((row.id, row.previous_hash if row.row_hash else None))
            if altered:
                content_mismatch_ids.append(row.id)
            if (not linked or altered) and len(first_details) < MAX_DETAILED_FINDINGS:
                first_details[row.id] = {
                    "id": row.id, "expected_previous_hash": expected,
                    "actual_previous_hash": row.previous_hash, "row_hash": row.row_hash,
                    "recomputed_hash": row.computed}
            expected = row.row_hash if row.row_hash else expected
            chain_head = row.row_hash or chain_head
            last_id = row.id
            verified += 1
        if progress:
            progress(verified, last_id)
        if len(rows) < limit and max_rows is None:
            break

    fork_ids, true_break_ids = classify_links(session, link_candidates, _chain_roots(session),
                                              serialized_from=first_serialized_id(session))

    witness = None
    if witness_heads is not None:
        from app.services.audit_witness import check_heads

        witness = check_heads(session, witness_heads)
    total_entries = estimated_total(session)

    anchor_verification = None
    if anchor is not None:
        if anchor_verifier is None:
            anchor_verification = {"status": "unverified", "issues": [], "reasons": [
                "the anchor was not checked against its archive manifest (no witness bucket access)"],
                "lineage": []}
        else:
            session.rollback()  # no snapshot or lock is held while S3 answers
            anchor_verification = anchor_verifier(anchor)
    anchor_failed = bool(anchor_verification) and anchor_verification["status"] == "failed"
    if witness is not None:
        from app.services.audit_witness import report, resolve_foreign_chains

        witness = report(resolve_foreign_chains(witness, anchor, anchor_verification))

    issues = []
    if content_mismatch_ids:
        issues.append((content_mismatch_ids[0], "Content altered: recomputed hash does not match row_hash"))
    if true_break_ids:
        issues.append((true_break_ids[0], "True break: previous_hash matches no earlier entry"))
    if fork_ids:
        issues.append((fork_ids[0], "Fork: previous_hash is an earlier entry's row_hash, "
                                    "not the immediately preceding entry's"))
    if anchor_failed:
        issues.append((anchor["id"], "Anchor not verified: " + anchor_verification["issues"][0]))

    witness = witness or {}
    witness_count = witness.get("mismatches_count", 0)
    invalid_count = witness.get("invalid_heads_count", 0)
    unverified_continuations = witness.get("unverified_continuations_count", 0)
    witness_mismatch_ids = [m["id"] for m in witness.get("mismatches", []) if m.get("id") is not None]
    if witness_mismatch_ids:
        issues.append((min(witness_mismatch_ids),
                       "Witness mismatch: a published chain head is missing or different"))
    first_break = None
    if issues:
        first_id, issue = min(issues)
        first_break = dict(first_details.get(first_id, {"id": first_id}), issue=issue)
    elif witness_count:
        first_break = {"id": None, "issue": "Witness mismatch: " + witness["mismatches"][0]["issue"]}
    elif invalid_count:
        first = witness["invalid_heads"][0]
        first_break = {"id": None, "issue": f"Invalid witness objects: {invalid_count} "
                                            f"(first: {first['key']}: {first['reason']})"}

    if content_mismatch_ids or true_break_ids or witness_count or invalid_count or anchor_failed:
        status = "broken"
    elif (anchor_verification and anchor_verification["status"] != "verified") or unverified_continuations:
        status = "unverified"
    elif fork_ids:
        status = "intact_with_forks"
    else:
        status = "valid"
    return {
        "status": status,
        "total_entries": total_entries,
        "unhashed_entries": unhashed,
        "verified": verified,
        "content_mismatches": len(content_mismatch_ids),
        "forks": len(fork_ids),
        "true_breaks": len(true_break_ids),
        "first_content_mismatch_id": content_mismatch_ids[0] if content_mismatch_ids else None,
        "first_fork_id": fork_ids[0] if fork_ids else None,
        "first_true_break_id": true_break_ids[0] if true_break_ids else None,
        "breaks": len(content_mismatch_ids) + len(fork_ids) + len(true_break_ids)
        + witness_count + invalid_count + int(anchor_failed),
        "witness_mismatches": witness_count,
        "invalid_witness_objects": invalid_count,
        "first_witness_mismatch_id": min(witness_mismatch_ids) if witness_mismatch_ids else None,
        "anchor_verification": anchor_verification,
        "fork_reason": FORK_REASON if fork_ids else None,
        "witness": witness if witness_heads is not None else None,
        "first_break": first_break,
        "chain_head": chain_head,
        "anchor": anchor,
        "complete": complete,
        "next_after_id": None if complete else last_id,
        "expected_previous_hash": None if complete else expected,
    }


def insert_anchor(session, *, archive_id: str, archive_sha256: str, archived_chain_head: str,
                  archived_entries: int, manifest_key: str, manifest_sha256: str,
                  note: str | None = None) -> int:
    """Insert the ANCHOR row (the database's audit_log must be empty).

    Operators anchor through ``app.services.audit_archive.anchor_from_manifest``
    (``python -m cli audit-anchor --manifest``), which takes every value from
    a verified archive manifest.
    """
    if not _is_postgres(session):
        raise AuditChainError("Anchors require PostgreSQL.")
    archive_sha256 = archive_sha256.strip().lower()
    archived_chain_head = archived_chain_head.strip().lower()
    manifest_sha256 = (manifest_sha256 or "").strip().lower()
    if not HEX64.match(archive_sha256) or not HEX64.match(archived_chain_head) \
            or not HEX64.match(manifest_sha256):
        raise AuditChainError("archive_sha256, archived_chain_head and manifest_sha256 must be 64 hex characters")
    if not archive_id or len(archive_id) > 36:
        raise AuditChainError("archive_id must be 1-36 characters")
    if not manifest_key or not manifest_key.startswith("archives/") \
            or not manifest_key.endswith(".manifest.json"):
        raise AuditChainError("manifest_key must be archives/<chain id>/<name>.manifest.json")
    return int(session.execute(
        text("SELECT audit_log_insert_anchor(:archive_id, :sha, :head, :entries, :mkey, :msha, :note)"),
        {"archive_id": archive_id, "sha": archive_sha256, "head": archived_chain_head,
         "entries": int(archived_entries), "mkey": manifest_key, "msha": manifest_sha256, "note": note},
    ).scalar())
