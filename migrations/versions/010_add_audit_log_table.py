"""Add audit_log table with PostgreSQL triggers for change tracking.

Revision ID: 010
Revises: 009
Create Date: 2026-04-05
"""
from alembic import op
import sqlalchemy as sa

revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None

AUDITED_TABLES = [
    "controls",
    "test_records",
    "policies",
    "evidence",
    "systems",
    "vendors",
    "risk_register",
    "pentest_findings",
    "team_members",
]


def upgrade():
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("table_name", sa.String(100), nullable=False),
        sa.Column("record_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(10), nullable=False),
        sa.Column("old_values", sa.JSON),
        sa.Column("new_values", sa.JSON),
        sa.Column("changed_by", sa.String(36)),
        sa.Column(
            "changed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_audit_log_table_record", "audit_log", ["table_name", "record_id"])
    op.create_index("ix_audit_log_changed_at", "audit_log", ["changed_at"])
    op.create_index("ix_audit_log_changed_by", "audit_log", ["changed_by"])

    # Create the generic audit trigger function (PostgreSQL only)
    op.execute("""
        CREATE OR REPLACE FUNCTION audit_trigger_func()
        RETURNS TRIGGER AS $$
        DECLARE
            changed_by_val VARCHAR(36);
        BEGIN
            BEGIN
                changed_by_val := current_setting('app.current_team_member', true);
            EXCEPTION WHEN OTHERS THEN
                changed_by_val := NULL;
            END;

            IF TG_OP = 'INSERT' THEN
                INSERT INTO audit_log (table_name, record_id, action, old_values, new_values, changed_by)
                VALUES (TG_TABLE_NAME, NEW.id, 'INSERT', NULL, to_jsonb(NEW), changed_by_val);
                RETURN NEW;
            ELSIF TG_OP = 'UPDATE' THEN
                INSERT INTO audit_log (table_name, record_id, action, old_values, new_values, changed_by)
                VALUES (TG_TABLE_NAME, NEW.id, 'UPDATE', to_jsonb(OLD), to_jsonb(NEW), changed_by_val);
                RETURN NEW;
            ELSIF TG_OP = 'DELETE' THEN
                INSERT INTO audit_log (table_name, record_id, action, old_values, new_values, changed_by)
                VALUES (TG_TABLE_NAME, OLD.id, 'DELETE', to_jsonb(OLD), NULL, changed_by_val);
                RETURN OLD;
            END IF;
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
    """)

    # Attach triggers to all compliance tables
    for table in AUDITED_TABLES:
        op.execute(f"""
            CREATE TRIGGER audit_{table}
            AFTER INSERT OR UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION audit_trigger_func();
        """)


def downgrade():
    for table in reversed(AUDITED_TABLES):
        op.execute(f"DROP TRIGGER IF EXISTS audit_{table} ON {table};")
    op.execute("DROP FUNCTION IF EXISTS audit_trigger_func();")
    op.drop_index("ix_audit_log_changed_by")
    op.drop_index("ix_audit_log_changed_at")
    op.drop_index("ix_audit_log_table_record")
    op.drop_table("audit_log")
