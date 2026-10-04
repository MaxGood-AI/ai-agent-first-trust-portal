"""Verify an archived audit chain from its database dump (``python -m cli audit-verify-archive``).

The archive manifest proves which dump was archived (key, version, size and
SHA-256) and which chain head it ends at; the witness proves which heads were
published. This module checks what the dump itself CONTAINS, for an auditor
or operator:

1. the dump's SHA-256 and size equal the manifest's (``--manifest``);
2. its ``audit_log`` rows form a chain that verifies with the same rules as
   a live database (``audit_chain.verify_chain``: content hashes, links,
   forks before the first serialized row, rows from before the v2 trigger);
3. its chain id, final row (id and ``row_hash``) and row count equal the
   manifest's;
4. every head the witness published for that chain id (every object version
   under ``chain-heads/<chain id>/``) matches a row of the dump: the archive
   holds every published row.

How: one sequential pass over the dump (``pg_dump --format=custom``,
uncompressed or gzip-compressed; archive versions 1.12 to 1.16, PostgreSQL
12 to 17) hashes every byte and streams only the ``public.audit_log`` table
data, decompressed on the fly, into an UNLOGGED table in a scratch schema
(``COPY ... FROM STDIN``; never held in memory). The scratch table gets the
dump's own column types (parsed, not executed, from the dump's definition),
a primary key and statistics, then the chain is verified inside PostgreSQL.
The scratch schema is dropped afterwards unless ``keep`` is set. The scratch
database needs free space for the ``audit_log`` table (roughly its size in
the source database); no WAL is written for it.
"""

from __future__ import annotations

import functools
import hashlib
import io
import re
import uuid
import zlib

MAGIC = b"PGDMP"
FORMAT_CUSTOM = 1
BLK_DATA, BLK_BLOBS = 1, 3
OFFSET_POS_SET = 2
COMPRESSION = {0: "none", 1: "gzip", 2: "lz4", 3: "zstd"}
READ_CHUNK = 1024 * 1024
# The column types an audit_log may have; any other type is refused (the
# dump's definition is parsed, never executed).
ALLOWED_TYPES = re.compile(
    r"^(integer|bigint|smallint|text|json|jsonb|timestamp with time zone|timestamp without time zone|"
    r"character varying(\(\d+\))?|character\(\d+\)|boolean|uuid)$")
IDENTIFIER = re.compile(r'^(?:[a-z_][a-z0-9_]*|"[^"]+")$')


class DumpError(RuntimeError):
    """The file is not a readable pg_dump custom-format archive of a portal database."""


class HashingReader:
    """Reads a file sequentially, hashing every byte it passes over."""

    def __init__(self, handle):
        self.handle = handle
        self.sha256 = hashlib.sha256()
        self.size = 0

    def read(self, count: int) -> bytes:
        data = self.handle.read(count)
        self.sha256.update(data)
        self.size += len(data)
        return data

    def exact(self, count: int) -> bytes:
        data = self.read(count)
        if len(data) != count:
            raise DumpError("the dump is truncated")
        return data

    def skip(self, count: int) -> None:
        while count > 0:
            data = self.read(min(count, READ_CHUNK))
            if not data:
                raise DumpError("the dump is truncated")
            count -= len(data)

    def finish(self) -> None:
        while self.read(READ_CHUNK):
            pass


class CustomArchive:
    """Just enough of the pg_dump custom format to find and stream one table's data."""

    def __init__(self, reader: HashingReader):
        self.r = reader
        if reader.exact(5) != MAGIC:
            raise DumpError("not a pg_dump custom-format archive (use pg_dump --format=custom)")
        self.version = tuple(reader.exact(3))[:2]  # major, minor (the revision is always 0)
        if self.version < (1, 12) or self.version > (1, 16):
            raise DumpError(f"unsupported archive version {'.'.join(map(str, self.version))}")
        self.int_size, self.off_size = reader.exact(1)[0], reader.exact(1)[0]
        if reader.exact(1)[0] != FORMAT_CUSTOM:
            raise DumpError("not a custom-format archive (use pg_dump --format=custom)")
        if self.version >= (1, 15):
            self.compression = COMPRESSION.get(reader.exact(1)[0], "unknown")
        else:
            self.compression = "none" if self.read_int() == 0 else "gzip"
        if self.compression not in ("none", "gzip"):
            raise DumpError(f"the dump is {self.compression}-compressed; dump with --compress=gzip or none")
        for _ in range(7):  # creation time
            self.read_int()
        self.database = self.read_str()
        self.server_version = self.read_str()
        self.dump_version = self.read_str()
        self.toc = [self._read_toc_entry() for _ in range(self.read_int())]

    def read_int(self) -> int:
        sign = self.r.exact(1)[0]
        value = int.from_bytes(self.r.exact(self.int_size), "little")
        return -value if sign else value

    def read_str(self) -> str | None:
        length = self.read_int()
        if length < 0:
            return None
        return self.r.exact(length).decode("utf-8", "replace")

    def _read_toc_entry(self) -> dict:
        entry = {"dump_id": self.read_int(), "had_dumper": self.read_int()}
        self.read_str()  # table oid
        self.read_str()  # oid
        entry["tag"] = self.read_str()
        entry["desc"] = self.read_str()
        self.read_int()  # section
        entry["defn"] = self.read_str()
        self.read_str()  # drop statement
        entry["copy_stmt"] = self.read_str()
        entry["namespace"] = self.read_str()
        self.read_str()  # tablespace
        self.read_str()  # table access method
        if self.version >= (1, 16):
            self.read_int()  # relkind
        self.read_str()  # owner
        self.read_str()  # "with oids"
        while self.read_str() is not None:  # dependencies
            pass
        entry["data_state"] = self.r.exact(1)[0]
        self.r.exact(self.off_size)  # data offset (the file is read sequentially)
        return entry

    def find(self, namespace: str, tag: str) -> tuple[dict, dict]:
        table = next((e for e in self.toc if e["desc"] == "TABLE" and e["namespace"] == namespace
                      and e["tag"] == tag), None)
        data = next((e for e in self.toc if e["desc"] == "TABLE DATA" and e["namespace"] == namespace
                     and e["tag"] == tag), None)
        if table is None or data is None:
            raise DumpError(f"the dump has no data for {namespace}.{tag}")
        return table, data

    def _chunks(self):
        while True:
            length = self.read_int()
            if length <= 0:
                return
            yield self.r.exact(length)

    def data_stream(self, dump_id: int):
        """Skip data blocks until ``dump_id``'s; return its decompressed data as a file-like object."""
        while True:
            kind = self.r.read(1)
            if not kind:
                raise DumpError("the dump ends before the table's data")
            block_id = self.read_int()
            if kind[0] == BLK_DATA and block_id == dump_id:
                return _DecompressedStream(self._chunks(), self.compression)
            if kind[0] == BLK_BLOBS:
                while self.read_int() != 0:
                    for _ in self._chunks():
                        pass
            else:
                for _ in self._chunks():
                    pass


class _DecompressedStream(io.RawIOBase):
    def __init__(self, chunks, compression):
        self.chunks = chunks
        self.inflate = zlib.decompressobj() if compression == "gzip" else None
        self.buffer = b""
        self.done = False

    def readable(self):
        return True

    def read(self, size=-1):
        while not self.done and (size < 0 or len(self.buffer) < size):
            chunk = next(self.chunks, None)
            if chunk is None:
                if self.inflate is not None:
                    self.buffer += self.inflate.flush()
                self.done = True
                break
            self.buffer += self.inflate.decompress(chunk) if self.inflate is not None else chunk
        if size < 0:
            data, self.buffer = self.buffer, b""
        else:
            data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data

    def drain(self):
        while self.read(READ_CHUNK):
            pass


def _columns(table_entry: dict, data_entry: dict) -> tuple[list[str], list[tuple[str, str]]]:
    """(COPY column list, [(column, type)]) from the dump's definition, validated."""
    match = re.match(r"^COPY \S+ \((.*)\) FROM stdin;", data_entry["copy_stmt"] or "", re.S)
    if not match:
        raise DumpError("the dump's audit_log data has no COPY column list")
    copy_columns = [c.strip() for c in match.group(1).split(",")]
    body = re.search(r"\((.*)\);", table_entry["defn"] or "", re.S)
    if not body:
        raise DumpError("the dump has no definition for audit_log")
    types = {}
    for line in body.group(1).split("\n"):
        line = line.strip().rstrip(",")
        if not line or line.upper().startswith(("CONSTRAINT", "CHECK", "PRIMARY", "UNIQUE", "FOREIGN")):
            continue
        name, rest = line.split(" ", 1)
        column_type = re.split(r" (?:NOT NULL|DEFAULT|COLLATE|GENERATED|NULL)\b", rest)[0].strip()
        if not IDENTIFIER.match(name) or not ALLOWED_TYPES.match(column_type):
            raise DumpError(f"unexpected audit_log column in the dump: {line[:120]}")
        types[name] = column_type
    if any(c not in types or not IDENTIFIER.match(c) for c in copy_columns) or "id" not in copy_columns:
        raise DumpError("the dump's audit_log columns do not match its COPY data")
    return copy_columns, [(c, types[c]) for c in copy_columns]


def load_audit_log(dump_path: str, raw_connection, schema: str) -> dict:
    """Stream the dump's audit_log into ``schema.audit_log`` (UNLOGGED) through
    ``raw_connection`` (psycopg2); hash the whole file. Returns
    ``{"sha256", "size", "rows", "archive_version", "server_version"}``."""
    with open(dump_path, "rb") as handle:
        reader = HashingReader(handle)
        archive = CustomArchive(reader)
        table, data = archive.find("public", "audit_log")
        copy_columns, columns = _columns(table, data)
        cursor = raw_connection.cursor()
        cursor.execute(f"CREATE SCHEMA {schema}")
        cursor.execute(f"CREATE UNLOGGED TABLE {schema}.audit_log ("
                       + ", ".join(f"{name} {kind}" for name, kind in columns) + ")")
        stream = archive.data_stream(data["dump_id"])
        cursor.copy_expert(f"COPY {schema}.audit_log ({', '.join(copy_columns)}) FROM STDIN", stream,
                           size=READ_CHUNK)
        stream.drain()
        rows = cursor.rowcount
        reader.finish()
        cursor.execute(f"ALTER TABLE {schema}.audit_log ADD PRIMARY KEY (id)")
        cursor.execute(f"ANALYZE {schema}.audit_log")
        raw_connection.commit()
    return {"sha256": reader.sha256.hexdigest(), "size": reader.size, "rows": rows,
            "archive_version": ".".join(map(str, archive.version)), "server_version": archive.server_version}


def verify_archive_dump(dump_path: str, scratch_url: str, *, bucket: str | None = None, client=None,
                        manifest_key: str | None = None, keep: bool = False, progress=None) -> dict:
    """Load and verify (module docstring). ``result["ok"]`` is the overall verdict: true only
    when nothing failed (``issues``) and the dump was checked against both the witness (``bucket``)
    and the manifest (``manifest_key``); what was not checked is listed in ``unchecked``."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session

    from app.services import audit_archive, audit_witness
    from app.services.audit_chain import verify_chain

    manifest = None
    if manifest_key:
        manifest = _read_manifest(client, bucket, manifest_key)
    schema = f"audit_archive_{uuid.uuid4().hex[:12]}"
    issues: list[str] = []
    admin = create_engine(scratch_url)
    engine = create_engine(scratch_url, connect_args={"options": f"-c search_path={schema}"})
    try:
        raw = admin.raw_connection()
        try:
            loaded = load_audit_log(dump_path, raw, schema)
        finally:
            raw.close()
        with Session(engine) as session:
            chain = audit_witness.chain_id(session)
            last = session.execute(text(
                "SELECT id, row_hash FROM audit_log WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1")).first()
            heads = None
            if bucket and chain:
                heads = audit_witness.load_heads_s3(bucket, chain=chain, client=client)
            verifier = functools.partial(audit_archive.verify_anchor, bucket=bucket, client=client,
                                         heads=heads) if bucket else None
            result = verify_chain(session, progress=progress, witness_heads=heads, anchor_verifier=verifier)
    finally:
        engine.dispose()
        if not keep:
            with admin.begin() as conn:
                conn.execute(text(f"DROP SCHEMA IF EXISTS {schema} CASCADE"))
        admin.dispose()

    if result["status"] not in ("valid", "intact_with_forks"):
        issues.append(f"the archived chain does not verify: {result['status']} "
                      f"({(result.get('first_break') or {}).get('issue', '')})")
    if heads is not None and not heads["valid"] and not heads["invalid"]:
        issues.append(f"the witness published no head for chain {chain}")
    if manifest is not None:
        expected = {"archive_sha256": loaded["sha256"], "archive_size": loaded["size"], "chain_id": chain,
                    "final_row_id": last.id if last else None, "final_row_hash": last.row_hash if last else None,
                    "entries": loaded["rows"]}
        for field, value in expected.items():
            if manifest.get(field) != value:
                issues.append(f"the dump's {field} ({value}) is not the manifest's ({manifest.get(field)})")
    unchecked = []
    if not bucket:
        unchecked.append("not checked against the witness (no bucket): the published heads were not compared")
    if manifest is None:
        unchecked.append("not checked against an archive manifest (no --manifest): SHA-256, size, final row "
                         "and row count were not compared")
    return {"ok": not issues and not unchecked, "issues": issues, "unchecked": unchecked,
            "dump": loaded, "chain_id": chain,
            "final_row": {"id": last.id, "row_hash": last.row_hash} if last else None,
            "verify": result, "manifest_key": manifest_key, "scratch_schema": schema if keep else None}


def _read_manifest(client, bucket, key):
    from app.services import audit_archive

    versions = audit_archive._versions(client, bucket, key, exact=True)
    bodies = [audit_archive._read_version(client, bucket, item, audit_archive.MAX_MANIFEST_BYTES)
              for item in versions]
    if not bodies:
        raise DumpError(f"no archive manifest at {key}")
    if len({hashlib.sha256(b).hexdigest() for b in bodies}) != 1:
        raise DumpError(f"the manifest at {key} has differing versions")
    return audit_archive.parse_manifest(bodies[0])


__all__ = ["DumpError", "load_audit_log", "verify_archive_dump"]
