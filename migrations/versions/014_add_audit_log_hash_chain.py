"""Add hash chain columns to audit_log and update trigger.

Revision ID: 014
Revises: 013
Create Date: 2026-04-06
"""

from alembic import op
import sqlalchemy as sa

revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade():
    # Add hash chain columns
    op.add_column("audit_log", sa.Column("row_hash", sa.String(64), nullable=True))
    op.add_column("audit_log", sa.Column("previous_hash", sa.String(64), nullable=True))

    # Replace the trigger function with hash-chain-aware version
    op.execute("""
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

            -- Get the hash of the most recent audit log entry
            SELECT row_hash INTO prev_hash
            FROM audit_log
            ORDER BY id DESC
            LIMIT 1;

            IF prev_hash IS NULL THEN
                prev_hash := '0000000000000000000000000000000000000000000000000000000000000000';
            END IF;

            IF TG_OP = 'INSERT' THEN
                row_data := prev_hash || TG_TABLE_NAME || NEW.id || 'INSERT' || to_jsonb(NEW)::text;
                new_hash := encode(digest(row_data, 'sha256'), 'hex');
                INSERT INTO audit_log (table_name, record_id, action, old_values, new_values, changed_by, previous_hash, row_hash)
                VALUES (TG_TABLE_NAME, NEW.id, 'INSERT', NULL, to_jsonb(NEW), changed_by_val, prev_hash, new_hash);
                RETURN NEW;
            ELSIF TG_OP = 'UPDATE' THEN
                row_data := prev_hash || TG_TABLE_NAME || NEW.id || 'UPDATE' || to_jsonb(OLD)::text || to_jsonb(NEW)::text;
                new_hash := encode(digest(row_data, 'sha256'), 'hex');
                INSERT INTO audit_log (table_name, record_id, action, old_values, new_values, changed_by, previous_hash, row_hash)
                VALUES (TG_TABLE_NAME, NEW.id, 'UPDATE', to_jsonb(OLD), to_jsonb(NEW), changed_by_val, prev_hash, new_hash);
                RETURN NEW;
            ELSIF TG_OP = 'DELETE' THEN
                row_data := prev_hash || TG_TABLE_NAME || OLD.id || 'DELETE' || to_jsonb(OLD)::text;
                new_hash := encode(digest(row_data, 'sha256'), 'hex');
                INSERT INTO audit_log (table_name, record_id, action, old_values, new_values, changed_by, previous_hash, row_hash)
                VALUES (TG_TABLE_NAME, OLD.id, 'DELETE', to_jsonb(OLD), NULL, changed_by_val, prev_hash, new_hash);
                RETURN OLD;
            END IF;
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
    """)

    # Ensure pgcrypto extension is available for digest()
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")


def downgrade():
    # Restore the original trigger function without hash chain
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

    op.drop_column("audit_log", "previous_hash")
    op.drop_column("audit_log", "row_hash")
