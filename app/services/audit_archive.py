"""Archived audit chains: the archive manifest and anchor verification.

A database whose audit log continues an ARCHIVED chain starts with an ANCHOR
row (``audit_log_insert_anchor``). The anchor is not self-certifying: it names
an ARCHIVE MANIFEST, an object in the witness bucket (under Object Lock) that
the operator writes at cutover with operator credentials. The runtime role
cannot write ``archives/``.

Objects (witness bucket, ``AUDIT_WITNESS_BUCKET``)
--------------------------------------------------
- ``archives/<chain_id>/<name>``: the archive itself (the final database
  dump), uploaded with ``If-None-Match: *`` and a SHA-256 checksum (multipart
  above 64 MiB), or an object the operator uploaded earlier under
  ``archives/``.
- ``archives/<chain_id>/<name>.manifest.json`` (``trust-portal-archive-manifest/v1``,
  written once with ``If-None-Match: *``): ``archive_id`` (= ``<name>``),
  ``archive_key``, ``archive_version_id``, ``archive_size``,
  ``archive_sha256``, ``chain_id`` (the archived chain), ``final_row_id``,
  ``final_row_hash``, ``entries`` (rows in the archived ``audit_log``),
  ``verify`` (the archived chain's verification summary: ``status``,
  ``verified``, ``forks``, ``true_breaks``, ``content_mismatches``,
  ``unhashed_entries``), ``source_anchor`` (when the archived chain itself
  started from an anchor: that anchor's archive id and SHA-256, archived
  chain head, entry count and manifest key and SHA-256; else null),
  ``final_head_key`` (the archived chain's final head in ``chain-heads/``),
  ``database``, ``created_at`` and ``portal_version``.

``create_archive_manifest`` (``python -m cli audit-archive-manifest``) reads
the chain from the database being archived (every writer stopped), hashes the
dump while streaming it, uploads it (or pins an existing ``archives/``
object), publishes the archived chain's final head to ``chain-heads/`` and
writes the manifest. ``anchor_from_manifest`` (``python -m cli
audit-anchor``) reads the manifest, checks it with the rules below,
inserts the anchor, which records the manifest's key and SHA-256 and copies
the archive SHA-256, final row hash, entry count and archive id from it, and
arms the witness in the same transaction. ``AUDIT_WITNESS_DISABLED`` blocks
writing a manifest.

Anchor verification (``verify_anchor``)
---------------------------------------
The anchor is ``verified`` only when all of these hold:

0. the anchor's manifest key is ``archives/<chain id>/<name>.manifest.json``
   (a prefix the runtime role cannot write) and the manifest names that
   chain id and name;
1. every version of the object at the anchor's manifest key has the SHA-256
   the anchor records (and at least one exists);
2. the manifest's ``archive_sha256``, ``final_row_hash``, ``archive_id`` and
   ``entries`` equal the anchor's ``archive_sha256``, ``previous_hash``
   (archived chain head), ``archive_id`` and ``archived_entries``;
3. the archive object exists (the version the manifest pins) with the stated
   size, and, with ``rehash=True``, its bytes hash to ``archive_sha256``;
4. the witness published a head for the manifest's ``chain_id`` with id
   ``final_row_id`` and row hash ``final_row_hash``, no published head of that
   chain differs from it, none has a larger id (the archive holds every
   published row), and no invalid witness object lies under that chain's
   prefix (the same head scan, and the same key-authoritative parsing, as the
   rest of the verification: ``audit_witness.scan_heads``);
5. when the manifest records a ``source_anchor``, that earlier anchor
   verifies against its own manifest by the same rules (at most 16
   generations).

Each verified manifest joins the ``lineage`` (chain id, final row id and
hash): the only way a published chain other than the current one is
accepted (``audit_witness.resolve_foreign_chains``). Anything else is
``failed``. Without read access to the witness bucket (no
bucket configured, access denied, bucket unreachable) the anchor is
``unverified``: it is never reported as valid on the anchor's own word.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone

from sqlalchemy import text

FORMAT = "trust-portal-archive-manifest/v1"
PREFIX = "archives/"
MANIFEST_SUFFIX = ".manifest.json"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,35}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX16 = re.compile(r"^[0-9a-f]{16}$")
MANIFEST_KEY = re.compile(r"^archives/([0-9a-f]{16})/([A-Za-z0-9][A-Za-z0-9._-]{0,35})\.manifest\.json$")
PART_SIZE = 64 * 1024 * 1024
HASH_CHUNK = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_LINEAGE = 16
SOURCE_ANCHOR_FIELDS = ("archive_id", "archive_sha256", "archived_chain_head", "archived_entries",
                        "archive_manifest_key", "archive_manifest_sha256")

# S3 error codes meaning "the object is not there" (evidence); every other
# failure to read means the verifier could not look (no access, unreachable).
ABSENT_CODES = {"NoSuchKey", "NoSuchVersion", "404", "NotFound"}


class ArchiveError(RuntimeError):
    """An archive manifest cannot be written or used."""


class WitnessDisabledError(ArchiveError):
    """``AUDIT_WITNESS_DISABLED`` is set: nothing is written to the witness bucket."""


class _NoAccess(Exception):
    """The verifier could not read the witness bucket."""


def archive_object_key(chain: str, name: str) -> str:
    return f"{PREFIX}{chain}/{name}"


def manifest_object_key(chain: str, name: str) -> str:
    return f"{PREFIX}{chain}/{name}{MANIFEST_SUFFIX}"


def operator_s3_client():
    """S3 client for the operator commands: the default AWS credential chain
    (the operator's own credentials), never the runtime role, which cannot
    write ``archives/``."""
    import boto3
    from botocore.config import Config

    from app.services.aws_session import default_region

    region = default_region()
    session = boto3.Session(region_name=region) if region else boto3.Session()
    return session.client("s3", config=Config(
        connect_timeout=10, read_timeout=120, retries={"max_attempts": 5, "mode": "standard"}))


def sha256_file(path: str) -> tuple[str, int]:
    """(hex SHA-256, size) of a local file, read in bounded chunks."""
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as handle:
        while chunk := handle.read(HASH_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _error_code(exc) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


def _versions(client, bucket: str, prefix: str, *, exact: bool) -> list[dict]:
    """Every object version under ``prefix`` (exactly ``prefix`` when ``exact``)."""
    found = []
    paginator = client.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for item in page.get("Versions", []):
            if not exact or item["Key"] == prefix:
                found.append(item)
    return found


def _read_version(client, bucket: str, item: dict, limit: int) -> bytes:
    kwargs = {"Bucket": bucket, "Key": item["Key"]}
    if item.get("VersionId") and item["VersionId"] != "null":
        kwargs["VersionId"] = item["VersionId"]
    body = client.get_object(**kwargs)["Body"].read(limit + 1)
    if len(body) > limit:
        raise ArchiveError(f"{item['Key']} is larger than {limit} bytes")
    return body


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_manifest(body: bytes) -> dict:
    """The manifest object, validated; raises ArchiveError."""
    try:
        manifest = json.loads(body)
    except ValueError as exc:
        raise ArchiveError(f"the manifest is not JSON: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise ArchiveError(f"the manifest is not a {FORMAT} object")
    checks = {
        "archive_id": lambda v: isinstance(v, str) and NAME_RE.match(v),
        "archive_key": lambda v: isinstance(v, str) and v.startswith(PREFIX) and len(v) <= 1024,
        "archive_version_id": lambda v: v is None or isinstance(v, str),
        "archive_size": lambda v: isinstance(v, int) and not isinstance(v, bool) and v >= 0,
        "archive_sha256": lambda v: isinstance(v, str) and HEX64.match(v),
        "chain_id": lambda v: isinstance(v, str) and HEX16.match(v),
        "final_row_id": lambda v: isinstance(v, int) and not isinstance(v, bool) and v > 0,
        "final_row_hash": lambda v: isinstance(v, str) and HEX64.match(v),
        "entries": lambda v: isinstance(v, int) and not isinstance(v, bool) and v >= 0,
        "verify": lambda v: isinstance(v, dict),
        "created_at": lambda v: isinstance(v, str),
    }
    for field, valid in checks.items():
        if not valid(manifest.get(field)):
            raise ArchiveError(f"the manifest's {field} is missing or invalid")
    source = manifest.get("source_anchor")
    if source is not None and (not isinstance(source, dict)
                               or any(not source.get(field) and source.get(field) != 0
                                      for field in SOURCE_ANCHOR_FIELDS)):
        raise ArchiveError("the manifest's source_anchor is invalid")
    return manifest


# --------------------------------------------------------------------------
# Writing (operator credentials)
# --------------------------------------------------------------------------

def _refuse_existing(client, bucket: str, key: str) -> None:
    if _versions(client, bucket, key, exact=True):
        raise ArchiveError(f"an object already exists at {key}; choose another --name")


def upload_archive(client, bucket: str, key: str, path: str, *, part_size: int = PART_SIZE) -> dict:
    """Upload ``path`` to ``key`` once (``If-None-Match: *``), hashing exactly
    the bytes sent. Returns ``{"version_id", "sha256", "size"}``."""
    _refuse_existing(client, bucket, key)
    size = os.path.getsize(path)
    digest = hashlib.sha256()
    try:
        if size <= part_size:
            with open(path, "rb") as handle:
                data = handle.read()
            digest.update(data)
            response = client.put_object(Bucket=bucket, Key=key, Body=data,
                                         ContentType="application/octet-stream",
                                         ChecksumAlgorithm="SHA256", IfNoneMatch="*",
                                         ServerSideEncryption="AES256")
            stored = response.get("ChecksumSHA256")
            if stored and base64.b64decode(stored).hex() != digest.hexdigest():
                raise ArchiveError(f"S3 stored different bytes at {key} than were sent")
            return {"version_id": response.get("VersionId"), "sha256": digest.hexdigest(), "size": len(data)}
        upload = client.create_multipart_upload(Bucket=bucket, Key=key, ContentType="application/octet-stream",
                                                ChecksumAlgorithm="SHA256", ServerSideEncryption="AES256")
        upload_id, parts, sent = upload["UploadId"], [], 0
        try:
            with open(path, "rb") as handle:
                number = 1
                while chunk := handle.read(part_size):
                    digest.update(chunk)
                    sent += len(chunk)
                    part = client.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=number,
                                              Body=chunk, ChecksumAlgorithm="SHA256")
                    entry = {"PartNumber": number, "ETag": part["ETag"]}
                    if part.get("ChecksumSHA256"):
                        entry["ChecksumSHA256"] = part["ChecksumSHA256"]
                    parts.append(entry)
                    number += 1
            response = client.complete_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id,
                                                        MultipartUpload={"Parts": parts}, IfNoneMatch="*")
        except BaseException:
            client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
            raise
        return {"version_id": response.get("VersionId"), "sha256": digest.hexdigest(), "size": sent}
    except Exception as exc:
        if _error_code(exc) in ("PreconditionFailed", "412"):
            raise ArchiveError(f"an object already exists at {key}; choose another --name") from exc
        raise


def existing_archive(client, bucket: str, key: str, size: int) -> str | None:
    """Version id of the current object at ``key``; it must have ``size`` bytes."""
    if not key.startswith(PREFIX):
        raise ArchiveError(f"the archive key must be under {PREFIX}")
    latest = [v for v in _versions(client, bucket, key, exact=True) if v.get("IsLatest")]
    if not latest:
        raise ArchiveError(f"no archive object at {key}")
    if latest[0]["Size"] != size:
        raise ArchiveError(f"the object at {key} has {latest[0]['Size']} bytes; the dump has {size}")
    version = latest[0].get("VersionId")
    return None if version in (None, "null") else version


def write_manifest(client, bucket: str, key: str, manifest: dict) -> dict:
    """Write the manifest once (``If-None-Match: *``). Returns ``{"key", "sha256", "version_id"}``."""
    body = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")
    try:
        response = client.put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/json",
                                     ChecksumAlgorithm="SHA256", IfNoneMatch="*",
                                     ServerSideEncryption="AES256")
    except Exception as exc:
        if _error_code(exc) in ("PreconditionFailed", "412"):
            raise ArchiveError(f"a manifest already exists at {key}; choose another --name") from exc
        raise
    return {"key": key, "sha256": _sha(body), "version_id": response.get("VersionId")}


def create_archive_manifest(session, *, bucket: str, client, dump_path: str, name: str,
                            archive_key: str | None = None, part_size: int = PART_SIZE) -> dict:
    """Archive the chain of the database ``session`` reads: see the module docstring.

    Every writer to that database must be stopped: the chain head is read
    before and after verification and must not move.
    """
    from app.runtime_config import witness_disabled
    from app.services.audit_chain import verify_chain
    from app.services.audit_witness import current_head, publish_head

    if witness_disabled():
        raise WitnessDisabledError("AUDIT_WITNESS_DISABLED is set: no manifest is written")
    if not NAME_RE.match(name or ""):
        raise ArchiveError("--name must be 1-36 characters: letters, digits, '.', '_' or '-'")
    if not os.path.isfile(dump_path):
        raise ArchiveError(f"no dump file at {dump_path}")

    head = current_head(session)
    if head is None:
        raise ArchiveError("the audit log has no hash chain to archive")
    summary = verify_chain(session, anchor_verifier=lambda anchor: verify_anchor(
        anchor, bucket=bucket, client=client))
    moved = current_head(session)
    if summary.get("chain_head") != head["row_hash"] or moved is None or moved["id"] != head["id"]:
        raise ArchiveError("the audit log changed while it was being archived: stop every writer first")
    entries = int(session.execute(text("SELECT count(*) FROM audit_log")).scalar())
    session.rollback()

    chain = head["chain_id"]
    if archive_key:
        sha256, size = sha256_file(dump_path)
        archive = {"key": archive_key, "sha256": sha256, "size": size,
                   "version_id": existing_archive(client, bucket, archive_key, size)}
    else:
        archive_key = archive_object_key(chain, name)
        uploaded = upload_archive(client, bucket, archive_key, dump_path, part_size=part_size)
        archive = dict(uploaded, key=archive_key)
    manifest_key = manifest_object_key(chain, name)
    _refuse_existing(client, bucket, manifest_key)

    published = publish_head(session, bucket=bucket, client=client, head=head, require_armed=False)
    if not published:
        raise ArchiveError("the archived chain's final head was not published")
    source = summary.get("anchor")
    manifest = {
        "format": FORMAT,
        "archive_id": name,
        "archive_key": archive["key"],
        "archive_version_id": archive["version_id"],
        "archive_size": archive["size"],
        "archive_sha256": archive["sha256"],
        "chain_id": chain,
        "final_row_id": head["id"],
        "final_row_hash": head["row_hash"],
        "entries": entries,
        "verify": {key: summary.get(key) for key in (
            "status", "verified", "forks", "true_breaks", "content_mismatches", "unhashed_entries")},
        "source_anchor": {field: source.get(field) for field in SOURCE_ANCHOR_FIELDS} if source else None,
        "final_head_key": published["key"],
        "database": head.get("database"),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "portal_version": head.get("portal_version"),
    }
    written = write_manifest(client, bucket, manifest_key, manifest)
    return {"manifest_key": manifest_key, "manifest_sha256": written["sha256"], "manifest": manifest}


def anchor_from_manifest(session, *, bucket: str, client, manifest_key: str, note: str | None = None) -> dict:
    """Check the manifest at ``manifest_key`` and anchor the empty audit log
    of ``session``'s database to it (owner role), then arm the witness in the
    same transaction. Nothing is inserted unless the anchor it would create
    verifies."""
    from app.services.audit_chain import insert_anchor
    from app.services.audit_witness import arm

    if not MANIFEST_KEY.match(manifest_key):
        raise ArchiveError(f"the manifest key must be {PREFIX}<chain id>/<name>{MANIFEST_SUFFIX}")
    try:
        versions = _versions(client, bucket, manifest_key, exact=True)
        bodies = [_read_version(client, bucket, item, MAX_MANIFEST_BYTES) for item in versions]
    except ArchiveError:
        raise
    except Exception as exc:  # noqa: BLE001 - reported to the operator
        raise ArchiveError(f"cannot read {manifest_key}: {exc}") from exc
    if not bodies:
        raise ArchiveError(f"no archive manifest at {manifest_key}")
    if len({_sha(body) for body in bodies}) != 1:
        raise ArchiveError(f"the manifest at {manifest_key} has differing versions")
    manifest = parse_manifest(bodies[0])
    anchor = {
        "archive_id": manifest["archive_id"],
        "archive_sha256": manifest["archive_sha256"],
        "archived_chain_head": manifest["final_row_hash"],
        "archived_entries": manifest["entries"],
        "archive_manifest_key": manifest_key,
        "archive_manifest_sha256": _sha(bodies[0]),
    }
    check = verify_anchor(anchor, bucket=bucket, client=client)
    if check["status"] != "verified":
        raise ArchiveError("the manifest does not verify: " + "; ".join(check["issues"] or check["reasons"]))
    anchor_id = insert_anchor(session, archive_id=anchor["archive_id"], archive_sha256=anchor["archive_sha256"],
                              archived_chain_head=anchor["archived_chain_head"],
                              archived_entries=anchor["archived_entries"], manifest_key=manifest_key,
                              manifest_sha256=anchor["archive_manifest_sha256"], note=note)
    arm(session, note=f"cutover: anchored to {manifest_key}")
    return {"anchor_id": anchor_id, "manifest": manifest, "anchor": anchor}


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------

def _classify_read_failure(exc) -> str:
    """For an S3/botocore failure: the error code when it proves the object is
    absent; otherwise raise _NoAccess (the verifier could not look). Any other
    exception is returned as a finding: verification fails closed."""
    from botocore.exceptions import BotoCoreError, ClientError

    if isinstance(exc, ClientError):
        code = _error_code(exc)
        if code in ABSENT_CODES:
            return f"an object the manifest names is missing ({code})"
        raise _NoAccess(f"cannot read the witness bucket ({code or 'ClientError'})") from exc
    if isinstance(exc, BotoCoreError):
        raise _NoAccess(f"cannot read the witness bucket ({exc.__class__.__name__})") from exc
    return f"the anchor could not be checked: {exc.__class__.__name__}: {exc}"


def _check_final_head(client, bucket: str, manifest: dict, issues: list[str], heads: dict | None) -> dict:
    """The archived chain's final head must be published, and nothing after it.

    Uses the verifier's own head scan when given (one source of head ids for
    the whole verification), else scans ``chain-heads/<chain id>/``; the key
    is authoritative and invalid objects count against the archive.
    """
    from app.services.audit_witness import key_parts, scan_heads

    chain, final_id, final_hash = manifest["chain_id"], manifest["final_row_id"], manifest["final_row_hash"]
    prefix = f"chain-heads/{chain}/"
    scan = heads if heads is not None else scan_heads(client, bucket, prefix)
    valid = [e for e in scan["valid"] if key_parts(e["key"])[0] == chain]
    invalid = [e for e in scan["invalid"] if e["key"].startswith(prefix)]
    published = [e["key"] for e in valid
                 if e["head"]["id"] == final_id and e["head"]["row_hash"] == final_hash]
    differing = [e["key"] for e in valid
                 if e["head"]["id"] == final_id and e["head"]["row_hash"] != final_hash]
    later = sorted({e["head"]["id"] for e in valid if e["head"]["id"] > final_id})
    if invalid:
        issues.append(f"{len(invalid)} invalid witness object(s) under {prefix} "
                      f"(first: {invalid[0]['key']}: {invalid[0]['reason']})")
    if not published:
        issues.append(f"the witness never published the archived chain's final head (row {final_id}) "
                      f"under {prefix}")
    if differing:
        issues.append(f"a published head for row {final_id} of the archived chain differs from the manifest")
    if later:
        issues.append(f"the witness published a head of the archived chain after its final row "
                      f"(row {later[-1]}): the archive does not hold every published row")
    return {"chain_id": chain, "final_row_id": final_id, "published_keys": published}


def _rehash(client, bucket: str, key: str, version_id: str | None) -> str:
    kwargs = {"Bucket": bucket, "Key": key}
    if version_id:
        kwargs["VersionId"] = version_id
    digest = hashlib.sha256()
    for chunk in client.get_object(**kwargs)["Body"].iter_chunks(HASH_CHUNK):
        digest.update(chunk)
    return digest.hexdigest()


def verify_anchor(anchor: dict, *, bucket: str | None, client=None, rehash: bool = False,
                  heads: dict | None = None) -> dict:
    """Check an anchor against its archive manifest, and that manifest's own
    source anchor against its manifest, back to the first generation
    (module docstring).

    Returns ``{"status": "verified" | "failed" | "unverified", "issues",
    "reasons", "lineage", "manifest_key", "manifest_versions", "archive",
    "archived_chain", "final_head", "rehashed"}``: ``issues`` explain a
    failure, ``reasons`` why the anchor could not be checked, ``lineage`` the
    verified manifests (chain id, final row id and hash) that continue
    earlier published chains. ``heads`` is the verifier's scan of
    ``chain-heads/`` (``audit_witness.load_heads_s3``), when it has one.
    """
    result = {"status": "unverified", "issues": [], "reasons": [], "lineage": [], "bucket": bucket,
              "manifest_key": anchor.get("archive_manifest_key"), "manifest_versions": 0,
              "archive": None, "archived_chain": None, "final_head": None, "rehashed": False}
    if not bucket:
        result["reasons"].append("no witness bucket: the archive manifest was not checked")
        return result
    try:
        if client is None:
            from app.services.audit_witness import s3_client

            client = s3_client()
        _check_generation(client, bucket, anchor, rehash, result, heads, depth=0)
    except _NoAccess as exc:
        result["reasons"].append(str(exc))
        result["lineage"] = []
        return result
    except ArchiveError as exc:
        result["issues"].append(str(exc))
    except Exception as exc:  # noqa: BLE001 - network, credentials, throttling, absent objects
        try:
            finding = _classify_read_failure(exc)
        except _NoAccess as no_access:
            result["reasons"].append(str(no_access))
            result["lineage"] = []
            return result
        result["issues"].append(finding)
    result["status"] = "failed" if result["issues"] else "verified"
    if result["issues"]:
        result["lineage"] = []
    return result


def _check_generation(client, bucket: str, anchor: dict, rehash: bool, result: dict, heads, depth: int) -> None:
    issues: list[str] = []
    label = f"generation {depth + 1}: " if depth else ""
    try:
        manifest = _check_manifest(client, bucket, anchor, rehash, result, heads, depth, issues)
    finally:
        result["issues"].extend(label + issue for issue in issues)
    if manifest is None or issues:
        return
    result["lineage"].append({"chain_id": manifest["chain_id"], "final_row_id": manifest["final_row_id"],
                              "final_row_hash": manifest["final_row_hash"],
                              "manifest_key": anchor["archive_manifest_key"]})
    source = manifest.get("source_anchor")
    if source:
        if depth + 1 >= MAX_LINEAGE:
            result["issues"].append(f"the archive lineage is longer than {MAX_LINEAGE} generations")
            return
        _check_generation(client, bucket, source, rehash, result, heads, depth + 1)


def _check_manifest(client, bucket: str, anchor: dict, rehash: bool, result: dict, heads, depth: int,
                    issues: list[str]) -> dict | None:
    key, pinned = anchor.get("archive_manifest_key"), anchor.get("archive_manifest_sha256")
    if not key or not pinned:
        issues.append("the anchor names no archive manifest (it was not created from a manifest "
                      "by python -m cli audit-anchor)")
        return None
    match = MANIFEST_KEY.match(key)
    if not match:
        issues.append(f"the anchor's manifest key {key[:200]} is not "
                      f"{PREFIX}<chain id>/<name>{MANIFEST_SUFFIX}")
        return None
    versions = _versions(client, bucket, key, exact=True)
    if depth == 0:
        result["manifest_versions"] = len(versions)
    if not versions:
        issues.append(f"no archive manifest at {key}")
        return None
    bodies = [_read_version(client, bucket, item, MAX_MANIFEST_BYTES) for item in versions]
    if any(_sha(body) != pinned for body in bodies):
        issues.append(f"the manifest at {key} is not the one the anchor names (manifest SHA-256 differs)")
        return None
    manifest = parse_manifest(bodies[0])
    if (manifest["chain_id"], manifest["archive_id"]) != (match.group(1), match.group(2)):
        issues.append(f"the manifest at {key} names another chain or archive than its key")
        return None
    _compare(anchor, manifest, issues)
    archive = _check_archive(client, bucket, manifest, issues)
    final_head = _check_final_head(client, bucket, manifest, issues, heads)
    if depth == 0:
        result["archived_chain"] = dict(manifest["verify"], chain_id=manifest["chain_id"],
                                        entries=manifest["entries"], final_row_id=manifest["final_row_id"])
        result["archive"], result["final_head"] = archive, final_head
    if rehash and not issues:
        recomputed = _rehash(client, bucket, manifest["archive_key"], archive["version_id"])
        archive["recomputed_sha256"] = recomputed
        result["rehashed"] = True
        if recomputed != manifest["archive_sha256"]:
            issues.append("the archive object's bytes do not hash to the manifest's archive_sha256")
    return manifest


def _compare(anchor: dict, manifest: dict, issues: list[str]) -> None:
    pairs = (
        ("archive_sha256", "archive_sha256", "the anchor's archive SHA-256 differs from the manifest's"),
        ("archived_chain_head", "final_row_hash",
         "the anchor's archived chain head (its previous_hash) is not the manifest's final row hash"),
        ("archive_id", "archive_id", "the anchor's archive id differs from the manifest's"),
        ("archived_entries", "entries", "the anchor's archived entry count differs from the manifest's"),
    )
    for anchor_field, manifest_field, message in pairs:
        if anchor.get(anchor_field) != manifest.get(manifest_field):
            issues.append(message)


def _check_archive(client, bucket: str, manifest: dict, issues: list[str]) -> dict:
    key, pinned = manifest["archive_key"], manifest.get("archive_version_id")
    versions = _versions(client, bucket, key, exact=True)
    if pinned:
        chosen = next((v for v in versions if v.get("VersionId") == pinned), None)
    else:
        chosen = next((v for v in versions if v.get("IsLatest")), None)
    info = {"key": key, "version_id": pinned, "size": manifest["archive_size"], "present": chosen is not None}
    if chosen is None:
        issues.append(f"the archive object {key}" + (f" (version {pinned})" if pinned else "") + " is missing")
    elif chosen["Size"] != manifest["archive_size"]:
        info["stored_size"] = chosen["Size"]
        issues.append(f"the archive object {key} has {chosen['Size']} bytes; the manifest states "
                      f"{manifest['archive_size']}")
    return info
