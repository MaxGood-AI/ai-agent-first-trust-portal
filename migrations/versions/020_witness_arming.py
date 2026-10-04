"""Audit witness arming and publication record.

- ``audit_witness_arming``: one row per arming of the audit witness. The
  witness publishes chain heads only once a row exists. Rows are inserted
  only through ``audit_witness_arm(note)``, a SECURITY DEFINER function that
  only the owner may execute; a guard trigger rejects every other insert and
  every update, delete and truncate, whatever the grants. The table is
  audited, so each arming is also an ``audit_log`` row.
- ``audit_witness_publications``: one row per head publication attempt that
  reached S3 (``published``, ``already`` or ``conflict``), written by the
  application; ``/api/health`` reports the latest ``published_at`` from it.
  Not audited (a publication must not change the chain head it reports).

Revision ID: 020
Revises: 019
Create Date: 2026-09-29
"""

from alembic import op
import sqlalchemy as sa

revision = "020"
down_revision = "019"
branch_labels = None
depends_on = None

SEARCH_PATH = "SET search_path = pg_catalog, pg_temp"

GUARD_FUNCTION = f"""
CREATE OR REPLACE FUNCTION public.audit_witness_arming_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
{SEARCH_PATH}
AS $$
BEGIN
    IF TG_OP = 'INSERT' AND pg_catalog.pg_has_role(
            current_user,
            (SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = TG_RELID),
            'MEMBER') THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'audit_witness_arming is written only by audit_witness_arm() (owner): % refused', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
"""

ARM_FUNCTION = f"""
CREATE OR REPLACE FUNCTION public.audit_witness_arm(p_note TEXT DEFAULT NULL)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
{SEARCH_PATH}
AS $$
DECLARE
    new_id INTEGER;
BEGIN
    IF p_note IS NOT NULL AND pg_catalog.length(p_note) > 500 THEN
        RAISE EXCEPTION 'note must be at most 500 characters';
    END IF;
    INSERT INTO public.audit_witness_arming (armed_at, armed_by, note)
    VALUES (pg_catalog.now(), session_user::text, p_note)
    RETURNING id INTO new_id;
    RETURN new_id;
END;
$$;
"""


def upgrade():
    op.create_table(
        "audit_witness_arming",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("armed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("armed_by", sa.String(128), nullable=False),
        sa.Column("note", sa.String(500), nullable=True),
    )
    op.create_table(
        "audit_witness_publications",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("head_id", sa.BigInteger, nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False),
        sa.Column("object_key", sa.String(512), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
    )
    op.create_index("ix_audit_witness_publications_published_at", "audit_witness_publications",
                    ["published_at"])
    if op.get_bind().dialect.name != "postgresql":
        return
    from importlib import import_module

    audit_table_sql = import_module("migrations.versions.016_audit_log_v2").audit_table_sql
    op.execute(GUARD_FUNCTION)
    op.execute(ARM_FUNCTION)
    op.execute("REVOKE EXECUTE ON FUNCTION public.audit_witness_arm(TEXT) FROM PUBLIC")
    op.execute("REVOKE EXECUTE ON FUNCTION public.audit_witness_arming_guard() FROM PUBLIC")
    op.execute("REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.audit_witness_arming FROM PUBLIC")
    op.execute("CREATE TRIGGER audit_witness_arming_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE "
               "ON public.audit_witness_arming FOR EACH STATEMENT EXECUTE FUNCTION public.audit_witness_arming_guard()")
    for statement in audit_table_sql("audit_witness_arming"):
        op.execute(statement)


def downgrade():
    op.execute("DROP TRIGGER IF EXISTS audit_audit_witness_arming ON audit_witness_arming;")
    op.execute("DROP TRIGGER IF EXISTS audit_lock_audit_witness_arming ON audit_witness_arming;")
    op.execute("DROP TRIGGER IF EXISTS audit_witness_arming_guard ON audit_witness_arming;")
    op.execute("DROP FUNCTION IF EXISTS audit_witness_arm(TEXT);")
    op.execute("DROP FUNCTION IF EXISTS audit_witness_arming_guard();")
    op.drop_table("audit_witness_publications")
    op.drop_table("audit_witness_arming")
