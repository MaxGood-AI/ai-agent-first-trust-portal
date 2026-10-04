"""Audit log v2: serialized, hardened hash chain; digested secrets; no-op
suppression; append-only guard; anchor support.

- ``audit_trigger_func()`` is replaced. It
  * writes only to ``public.audit_log`` (every object schema-qualified,
    ``search_path = pg_catalog, public, pg_temp``) and refuses to run for a
    table outside the ``public`` schema, so a temporary table can neither
    shadow ``audit_log`` nor borrow the trigger to forge audit rows;
  * replaces the columns named in the trigger arguments by ``sha256:<hex>``
    digests (API keys, stored credentials, file contents and bulky payloads
    never reach ``audit_log``); a bytea column's digest is that of its raw
    bytes, whatever the session's ``bytea_output``;
  * records nothing for an UPDATE whose only difference is ``updated_at`` or
    a running job's ``heartbeat_at``;
  * hashes ``changed_by`` and ``changed_at`` too (``hash_version = 2``);
  * runs as SECURITY DEFINER, so an application role without INSERT on
    ``audit_log`` still produces audit rows.
- ``audit_chain_lock()``, a BEFORE ... FOR EACH STATEMENT trigger on every
  audited table, takes the chain's transaction-scoped advisory lock before
  the statement takes any row lock. Chain appends are serialized, and two
  transactions can no longer deadlock on "row lock, then chain lock". The
  link tables ``policy_controls`` and ``vendor_systems`` (foreign keys to
  audited rows) take the same lock first.
- EXECUTE on these functions is revoked from PUBLIC: no role but the owner
  can attach them to a table of its own. TEMPORARY on the database is revoked
  from PUBLIC where the migrating role may do so.
- ``audit_log.hash_version`` (NULL = the v1 formula of migration 014) is a
  nullable column without a default: a metadata-only change, fast on a table
  of any size.
- ``audit_log_insert_anchor(...)`` (owner only) inserts the first row of a
  chain that continues an archived one: it records the archive manifest's key
  and SHA-256 (``app.services.audit_archive``) and who anchored it.
- ``audit_log_append_only()`` rejects UPDATE, DELETE and TRUNCATE on
  ``audit_log`` for every role.
- ``decision_log_sessions`` becomes an audited table. Decision-log entries
  are audited per upload, not per row: every stored version of a session's
  transcript is an audited ``decision_log_transcripts`` row (migration 018)
  carrying its entry count and entries digest, so one upload adds a
  constant number of audit rows however many entries it holds.

Revision ID: 016
Revises: 015
Create Date: 2026-09-28
"""

from alembic import op
import sqlalchemy as sa

revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None

# Advisory lock key serializing every append to the audit chain.
AUDIT_CHAIN_LOCK_KEY = 815000001

# table -> columns stored as digests rather than values
AUDITED_TABLES = {
    "controls": (),
    "test_records": (),
    "policies": (),
    "evidence": ("file_data",),
    "systems": (),
    "vendors": (),
    "risk_register": (),
    "pentest_findings": ("other_data",),
    "team_members": ("api_key", "api_key_hash"),
    "portal_settings": (),
    "collector_config": ("encrypted_credentials",),
    "collector_run": ("raw_log",),
    "collector_check_result": ("detail",),
    "decision_log_sessions": (),
}

# Only pg_catalog is searched for functions, operators and types (pg_temp is
# listed last so a temporary object can never shadow them); every table is
# schema-qualified. A role that can create objects in some schema therefore
# cannot plant an operator or function these SECURITY DEFINER bodies resolve.
# Tables that are not audited but hold foreign keys to audited tables: writing
# them takes key-share row locks on audited rows, so they take the chain lock
# first too (lock ordering: chain lock, then row locks).
CHAIN_LOCK_ONLY_TABLES = ("policy_controls", "vendor_systems")

SEARCH_PATH = "SET search_path = pg_catalog, pg_temp"
CAT = "OPERATOR(pg_catalog.||)"

CHAIN_LOCK_FUNCTION = f"""
CREATE OR REPLACE FUNCTION public.audit_chain_lock()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
{SEARCH_PATH}
AS $$
BEGIN
    IF TG_TABLE_SCHEMA <> 'public' THEN
        RAISE EXCEPTION 'audit triggers run only on tables in schema public (got %.%)',
            TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock({AUDIT_CHAIN_LOCK_KEY});
    RETURN NULL;
END;
$$;
"""

TRIGGER_FUNCTION = f"""
CREATE OR REPLACE FUNCTION public.audit_trigger_func()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
{SEARCH_PATH}
SET bytea_output = 'hex'
AS $$
DECLARE
    changed_by_val VARCHAR(36);
    old_json JSONB;
    new_json JSONB;
    rec_id TEXT;
    prev_hash VARCHAR(64);
    ts TIMESTAMPTZ := pg_catalog.now();
    col TEXT;
    col_is_bytea BOOLEAN;
    row_data TEXT;
BEGIN
    IF TG_TABLE_SCHEMA <> 'public' THEN
        RAISE EXCEPTION 'audit triggers run only on tables in schema public (got %.%)',
            TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
    END IF;

    changed_by_val := NULLIF(pg_catalog.current_setting('app.current_team_member', true), '');

    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        old_json := pg_catalog.to_jsonb(OLD);
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        new_json := pg_catalog.to_jsonb(NEW);
    END IF;

    -- Columns named in the trigger arguments are recorded as digests only:
    -- sha256 of the raw bytes of a bytea column (this function renders bytea
    -- as hex whatever the session's bytea_output), of the UTF-8 text of any
    -- other column.
    IF TG_NARGS > 0 THEN
        FOREACH col IN ARRAY TG_ARGV LOOP
            col_is_bytea := EXISTS (
                SELECT 1 FROM pg_catalog.pg_attribute AS att
                WHERE att.attrelid = TG_RELID AND att.attname = col::pg_catalog.name AND NOT att.attisdropped
                  AND att.atttypid = 'pg_catalog.bytea'::pg_catalog.regtype::pg_catalog.oid);
            IF old_json IS NOT NULL AND old_json ? col
               AND pg_catalog.jsonb_typeof(old_json -> col) <> 'null' THEN
                old_json := pg_catalog.jsonb_set(old_json, ARRAY[col], pg_catalog.to_jsonb(
                    'sha256:'::text {CAT} pg_catalog.encode(pg_catalog.sha256(CASE WHEN col_is_bytea
                        THEN pg_catalog.decode(pg_catalog.substr(old_json ->> col, 3), 'hex')
                        ELSE pg_catalog.convert_to(old_json ->> col, 'UTF8') END), 'hex')));
            END IF;
            IF new_json IS NOT NULL AND new_json ? col
               AND pg_catalog.jsonb_typeof(new_json -> col) <> 'null' THEN
                new_json := pg_catalog.jsonb_set(new_json, ARRAY[col], pg_catalog.to_jsonb(
                    'sha256:'::text {CAT} pg_catalog.encode(pg_catalog.sha256(CASE WHEN col_is_bytea
                        THEN pg_catalog.decode(pg_catalog.substr(new_json ->> col, 3), 'hex')
                        ELSE pg_catalog.convert_to(new_json ->> col, 'UTF8') END), 'hex')));
            END IF;
        END LOOP;
    END IF;

    -- An UPDATE that changes only bookkeeping columns (updated_at, a running
    -- job's heartbeat_at) is not an auditable change.
    IF TG_OP = 'UPDATE'
       AND (old_json - 'updated_at' - 'heartbeat_at') = (new_json - 'updated_at' - 'heartbeat_at') THEN
        RETURN NULL;
    END IF;

    rec_id := COALESCE(new_json, old_json) ->> 'id';

    -- Serialize chain appends (the statement-level audit_chain_lock trigger
    -- normally holds this lock already; taking it again is a no-op).
    PERFORM pg_catalog.pg_advisory_xact_lock({AUDIT_CHAIN_LOCK_KEY});
    SELECT a.row_hash INTO prev_hash FROM public.audit_log AS a ORDER BY a.id DESC LIMIT 1;
    IF prev_hash IS NULL THEN
        prev_hash := pg_catalog.repeat('0', 64);
    END IF;

    row_data := prev_hash::text {CAT} TG_TABLE_NAME::text {CAT} rec_id::text {CAT} TG_OP::text
        {CAT} COALESCE(changed_by_val::text, ''::text)
        {CAT} pg_catalog.to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        {CAT} COALESCE(old_json::text, ''::text) {CAT} COALESCE(new_json::text, ''::text);

    INSERT INTO public.audit_log (table_name, record_id, action, old_values, new_values,
                                  changed_by, changed_at, previous_hash, row_hash, hash_version)
    VALUES (TG_TABLE_NAME, rec_id, TG_OP, old_json, new_json,
            changed_by_val, ts, prev_hash,
            pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(row_data, 'UTF8')), 'hex'), 2);
    RETURN NULL;
END;
$$;
"""

ANCHOR_FUNCTION = f"""
CREATE OR REPLACE FUNCTION public.audit_log_insert_anchor(
    p_archive_id TEXT,
    p_archive_sha256 TEXT,
    p_archived_chain_head TEXT,
    p_archived_entries BIGINT,
    p_manifest_key TEXT,
    p_manifest_sha256 TEXT,
    p_note TEXT DEFAULT NULL
)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
{SEARCH_PATH}
AS $$
DECLARE
    new_json JSONB;
    rec_id TEXT;
    ts TIMESTAMPTZ := pg_catalog.now();
    row_data TEXT;
    new_id INTEGER;
BEGIN
    IF p_archive_id IS NULL OR pg_catalog.length(p_archive_id) = 0 OR pg_catalog.length(p_archive_id) > 36 THEN
        RAISE EXCEPTION 'archive id must be 1-36 characters';
    END IF;
    IF p_archive_sha256 IS NULL OR p_archive_sha256 !~ '^[0-9a-f]{{64}}$' THEN
        RAISE EXCEPTION 'archive sha256 must be 64 lowercase hex characters';
    END IF;
    IF p_archived_chain_head IS NULL OR p_archived_chain_head !~ '^[0-9a-f]{{64}}$' THEN
        RAISE EXCEPTION 'archived chain head must be 64 lowercase hex characters';
    END IF;
    IF p_manifest_key IS NULL OR pg_catalog.length(p_manifest_key) > 1024
            OR p_manifest_key !~ '^archives/[^[:cntrl:]]+[.]manifest[.]json$' THEN
        RAISE EXCEPTION 'manifest key must be archives/<chain id>/<name>.manifest.json';
    END IF;
    IF p_manifest_sha256 IS NULL OR p_manifest_sha256 !~ '^[0-9a-f]{{64}}$' THEN
        RAISE EXCEPTION 'manifest sha256 must be 64 lowercase hex characters';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock({AUDIT_CHAIN_LOCK_KEY});
    IF EXISTS (SELECT 1 FROM public.audit_log) THEN
        RAISE EXCEPTION 'audit_log is not empty: an anchor must be the first row of the chain';
    END IF;

    rec_id := p_archive_id;
    new_json := pg_catalog.jsonb_build_object(
        'archive_id', p_archive_id,
        'archive_sha256', p_archive_sha256,
        'archived_chain_head', p_archived_chain_head,
        'archived_entries', p_archived_entries,
        'archive_manifest_key', p_manifest_key,
        'archive_manifest_sha256', p_manifest_sha256,
        'anchored_by', session_user::text,
        'note', p_note
    );
    row_data := p_archived_chain_head::text {CAT} 'audit_log'::text {CAT} rec_id::text {CAT} 'ANCHOR'::text
        {CAT} ''::text
        {CAT} pg_catalog.to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        {CAT} ''::text {CAT} new_json::text;

    INSERT INTO public.audit_log (table_name, record_id, action, old_values, new_values,
                                  changed_by, changed_at, previous_hash, row_hash, hash_version)
    VALUES ('audit_log', rec_id, 'ANCHOR', NULL, new_json, NULL, ts,
            p_archived_chain_head,
            pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(row_data, 'UTF8')), 'hex'), 2)
    RETURNING id INTO new_id;
    RETURN new_id;
END;
$$;
"""

APPEND_ONLY_FUNCTION = f"""
CREATE OR REPLACE FUNCTION public.audit_log_append_only()
RETURNS TRIGGER
LANGUAGE plpgsql
{SEARCH_PATH}
AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
"""

REVOKE_EXECUTE = [
    "REVOKE EXECUTE ON FUNCTION public.audit_trigger_func() FROM PUBLIC",
    "REVOKE EXECUTE ON FUNCTION public.audit_chain_lock() FROM PUBLIC",
    "REVOKE EXECUTE ON FUNCTION public.audit_log_append_only() FROM PUBLIC",
    "REVOKE EXECUTE ON FUNCTION public.audit_log_insert_anchor(TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT) FROM PUBLIC",
]

# Revoke what the migrating role is allowed to revoke; a role that does not
# own the database or schema leaves those grants alone (the app-role
# provisioning step revokes them from the app role directly).
REVOKE_TEMP_AND_CREATE = """
DO $$
BEGIN
    BEGIN
        EXECUTE pg_catalog.format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', pg_catalog.current_database());
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'not revoking TEMPORARY from PUBLIC: the migrating role does not own the database';
    END;
    BEGIN
        EXECUTE 'REVOKE CREATE ON SCHEMA public FROM PUBLIC';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'not revoking CREATE on schema public from PUBLIC: not the schema owner';
    END;
END;
$$;
"""


# The migration-014 function, restored by downgrade().
V1_TRIGGER_FUNCTION = """
CREATE OR REPLACE FUNCTION audit_trigger_func()
RETURNS TRIGGER AS $$
DECLARE
    changed_by_val VARCHAR(36);
    prev_hash VARCHAR(64);
    new_hash VARCHAR(64);
    row_data TEXT;
BEGIN
    BEGIN
        changed_by_val := current_setting('app.current_team_member', true);
    EXCEPTION WHEN OTHERS THEN
        changed_by_val := NULL;
    END;
    SELECT row_hash INTO prev_hash FROM audit_log ORDER BY id DESC LIMIT 1;
    IF prev_hash IS NULL THEN
        prev_hash := '0000000000000000000000000000000000000000000000000000000000000000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        row_data := prev_hash || TG_TABLE_NAME || NEW.id || 'INSERT' || to_jsonb(NEW)::text;
        new_hash := encode(sha256(convert_to(row_data, 'UTF8')), 'hex');
        INSERT INTO audit_log (table_name, record_id, action, old_values, new_values, changed_by,
                               previous_hash, row_hash)
        VALUES (TG_TABLE_NAME, NEW.id, 'INSERT', NULL, to_jsonb(NEW), changed_by_val, prev_hash, new_hash);
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        row_data := prev_hash || TG_TABLE_NAME || NEW.id || 'UPDATE' || to_jsonb(OLD)::text || to_jsonb(NEW)::text;
        new_hash := encode(sha256(convert_to(row_data, 'UTF8')), 'hex');
        INSERT INTO audit_log (table_name, record_id, action, old_values, new_values, changed_by,
                               previous_hash, row_hash)
        VALUES (TG_TABLE_NAME, NEW.id, 'UPDATE', to_jsonb(OLD), to_jsonb(NEW), changed_by_val, prev_hash, new_hash);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        row_data := prev_hash || TG_TABLE_NAME || OLD.id || 'DELETE' || to_jsonb(OLD)::text;
        new_hash := encode(sha256(convert_to(row_data, 'UTF8')), 'hex');
        INSERT INTO audit_log (table_name, record_id, action, old_values, new_values, changed_by,
                               previous_hash, row_hash)
        VALUES (TG_TABLE_NAME, OLD.id, 'DELETE', to_jsonb(OLD), NULL, changed_by_val, prev_hash, new_hash);
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
"""


def _trigger_args(columns):
    return ", ".join(f"'{c}'" for c in columns)


def audit_table_sql(table: str, digested=()) -> list[str]:
    """Statements that make ``table`` audited (used by later migrations too)."""
    return [
        f"DROP TRIGGER IF EXISTS audit_{table} ON public.{table};",
        f"DROP TRIGGER IF EXISTS audit_lock_{table} ON public.{table};",
        f"CREATE TRIGGER audit_lock_{table} BEFORE INSERT OR UPDATE OR DELETE ON public.{table} "
        "FOR EACH STATEMENT EXECUTE FUNCTION public.audit_chain_lock();",
        f"CREATE TRIGGER audit_{table} AFTER INSERT OR UPDATE OR DELETE ON public.{table} "
        f"FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_func({_trigger_args(digested)});",
    ]


def upgrade():
    op.add_column(
        "audit_log",
        sa.Column("hash_version", sa.SmallInteger, nullable=True,
                  comment="Hash formula: NULL = v1 (migration 014), 2 = includes changed_by and changed_at"),
    )

    op.execute(CHAIN_LOCK_FUNCTION)
    op.execute(TRIGGER_FUNCTION)
    op.execute(ANCHOR_FUNCTION)
    op.execute(APPEND_ONLY_FUNCTION)
    for statement in REVOKE_EXECUTE:
        op.execute(statement)

    for table, digested in AUDITED_TABLES.items():
        for statement in audit_table_sql(table, digested):
            op.execute(statement)
    for table in CHAIN_LOCK_ONLY_TABLES:
        op.execute(
            f"CREATE TRIGGER audit_lock_{table} BEFORE INSERT OR UPDATE OR DELETE ON public.{table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION public.audit_chain_lock();"
        )

    op.execute(
        "CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON public.audit_log "
        "FOR EACH ROW EXECUTE FUNCTION public.audit_log_append_only();"
    )
    op.execute(
        "CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON public.audit_log "
        "FOR EACH STATEMENT EXECUTE FUNCTION public.audit_log_append_only();"
    )
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON public.audit_log FROM PUBLIC;")
    op.execute(REVOKE_TEMP_AND_CREATE)


def downgrade():
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;")
    op.execute("DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log;")
    op.execute("DROP FUNCTION IF EXISTS audit_log_append_only();")
    op.execute("DROP FUNCTION IF EXISTS audit_log_insert_anchor(TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT);")
    for table in list(AUDITED_TABLES) + list(CHAIN_LOCK_ONLY_TABLES):
        op.execute(f"DROP TRIGGER IF EXISTS audit_lock_{table} ON {table};")
    op.execute("DROP TRIGGER IF EXISTS audit_decision_log_sessions ON decision_log_sessions;")
    for table in AUDITED_TABLES:
        if table == "decision_log_sessions":
            continue
        op.execute(f"DROP TRIGGER IF EXISTS audit_{table} ON {table};")
        op.execute(
            f"CREATE TRIGGER audit_{table} AFTER INSERT OR UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION audit_trigger_func();"
        )
    op.execute(V1_TRIGGER_FUNCTION)
    op.execute("DROP FUNCTION IF EXISTS audit_chain_lock();")
    op.execute("GRANT EXECUTE ON FUNCTION audit_trigger_func() TO PUBLIC;")
    op.drop_column("audit_log", "hash_version")
