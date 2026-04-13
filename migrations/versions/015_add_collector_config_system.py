"""Add collector_config, collector_run, collector_check_result tables with audit triggers.

Revision ID: 015
Revises: 014
Create Date: 2026-04-12
"""

from alembic import op
import sqlalchemy as sa

revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None

NEW_AUDITED_TABLES = [
    "collector_config",
    "collector_run",
    "collector_check_result",
]


def upgrade():
    # collector_config — one row per named collector (aws, git, platform, policy, vendor)
    op.create_table(
        "collector_config",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(64), unique=True, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("credential_mode", sa.String(32), nullable=False, server_default="task_role"),
        sa.Column("encrypted_credentials", sa.LargeBinary, nullable=True),
        sa.Column("config", sa.JSON, nullable=True),
        sa.Column("schedule_cron", sa.String(64), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_status", sa.String(16), nullable=True),
        sa.Column("permission_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("permission_check_result", sa.JSON, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("team_members.id"), nullable=True),
        sa.Column("updated_by_id", sa.String(36), sa.ForeignKey("team_members.id"), nullable=True),
    )
    op.create_index("ix_collector_config_name", "collector_config", ["name"], unique=True)
    op.create_index("ix_collector_config_enabled", "collector_config", ["enabled"])
    op.create_index("ix_collector_config_next_run_at", "collector_config", ["next_run_at"])

    # collector_run — one row per collector execution
    op.create_table(
        "collector_run",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "collector_config_id",
            sa.String(36),
            sa.ForeignKey("collector_config.id"),
            nullable=False,
        ),
        sa.Column(
            "triggered_by_team_member_id",
            sa.String(36),
            sa.ForeignKey("team_members.id"),
            nullable=True,
        ),
        sa.Column("trigger_type", sa.String(16), nullable=False, server_default="manual"),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="running"),
        sa.Column("evidence_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("check_pass_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("check_fail_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("raw_log", sa.Text, nullable=True),
    )
    op.create_index("ix_collector_run_collector_config_id", "collector_run", ["collector_config_id"])
    op.create_index("ix_collector_run_started_at", "collector_run", ["started_at"])
    op.create_index("ix_collector_run_status", "collector_run", ["status"])

    # collector_check_result — one row per individual check within a run
    op.create_table(
        "collector_check_result",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "collector_run_id",
            sa.String(36),
            sa.ForeignKey("collector_run.id"),
            nullable=False,
        ),
        sa.Column("check_name", sa.String(128), nullable=False),
        sa.Column(
            "target_test_id",
            sa.String(36),
            sa.ForeignKey("test_records.id"),
            nullable=True,
        ),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column(
            "evidence_id",
            sa.String(36),
            sa.ForeignKey("evidence.id"),
            nullable=True,
        ),
        sa.Column("message", sa.Text, nullable=True),
        sa.Column("detail", sa.JSON, nullable=True),
    )
    op.create_index(
        "ix_collector_check_result_run_id",
        "collector_check_result",
        ["collector_run_id"],
    )
    op.create_index(
        "ix_collector_check_result_target_test_id",
        "collector_check_result",
        ["target_test_id"],
    )

    # Attach existing audit trigger to new tables (PostgreSQL only).
    # The audit_trigger_func was defined in migration 010 and updated with
    # hash chain support in migration 014.
    for table in NEW_AUDITED_TABLES:
        op.execute(f"""
            CREATE TRIGGER audit_{table}
            AFTER INSERT OR UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION audit_trigger_func();
        """)


def downgrade():
    for table in reversed(NEW_AUDITED_TABLES):
        op.execute(f"DROP TRIGGER IF EXISTS audit_{table} ON {table};")

    op.drop_index("ix_collector_check_result_target_test_id", table_name="collector_check_result")
    op.drop_index("ix_collector_check_result_run_id", table_name="collector_check_result")
    op.drop_table("collector_check_result")

    op.drop_index("ix_collector_run_status", table_name="collector_run")
    op.drop_index("ix_collector_run_started_at", table_name="collector_run")
    op.drop_index("ix_collector_run_collector_config_id", table_name="collector_run")
    op.drop_table("collector_run")

    op.drop_index("ix_collector_config_next_run_at", table_name="collector_config")
    op.drop_index("ix_collector_config_enabled", table_name="collector_config")
    op.drop_index("ix_collector_config_name", table_name="collector_config")
    op.drop_table("collector_config")
