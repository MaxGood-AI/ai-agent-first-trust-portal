"""Store API keys only as SHA-256 digests; revoke every key issued before now;
add the auth rate-limit table.

- ``team_members.api_key_hash`` (nullable, unique) holds ``sha256(key)`` in
  hex. A member whose ``api_key_hash`` is NULL has no usable key.
- Every key that existed before this revision is revoked: its plaintext was
  recorded in audit rows written before migration 016, and those rows are
  append-only, so the keys cannot be trusted. ``api_key`` is set to NULL (the
  column is dropped by a later release, keeping this release backward
  compatible), ``api_key_hash`` stays NULL, and ``key_rotation_required`` is
  set. Members keep their ids and history. An admin issues new keys with
  ``python -m cli regenerate-key`` or Admin > Team Members; while no active
  admin holds a key, ``/setup`` accepts the bootstrap token again.
- ``team_members.session_epoch``: browser sessions carry the epoch they were
  issued under; logging out increments it, so a copied session cookie stops
  working at once (server-side revocation).
- ``auth_rate_limit`` holds one counter per (bucket, client, fixed window);
  every attempt increments it with a single atomic upsert, so login, client
  login and setup are rate-limited exactly, across every process and node.

Revision ID: 017
Revises: 016
Create Date: 2026-09-28
"""

from alembic import op
import sqlalchemy as sa

revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("team_members", sa.Column(
        "api_key_hash", sa.String(64), nullable=True,
        comment="SHA-256 hex digest of the API key; NULL = no usable key"))
    op.add_column("team_members", sa.Column(
        "key_rotation_required", sa.Boolean, nullable=False, server_default=sa.text("false"),
        comment="True until an admin issues this member a new key"))
    op.add_column("team_members", sa.Column(
        "session_epoch", sa.Integer, nullable=False, server_default="0",
        comment="Incremented on logout; sessions of an earlier epoch are invalid"))
    op.create_index("ix_team_members_api_key_hash", "team_members", ["api_key_hash"], unique=True)
    op.alter_column("team_members", "api_key", nullable=True,
                    comment="Unused (keys are stored as api_key_hash); dropped by a later release")
    op.execute(
        "UPDATE team_members SET api_key = NULL, key_rotation_required = true "
        "WHERE api_key IS NOT NULL"
    )

    op.create_table(
        "auth_rate_limit",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("bucket", sa.String(32), nullable=False, comment="login | client_login | setup"),
        sa.Column("client_key", sa.String(128), nullable=False, comment="Client IP address"),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False,
                  comment="Start of the fixed rate-limit window"),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.UniqueConstraint("bucket", "client_key", "window_start", name="uq_auth_rate_limit_window"),
    )
    op.create_index("ix_auth_rate_limit_window_start", "auth_rate_limit", ["window_start"])


def downgrade():
    raise RuntimeError(
        "Revision 017 is irreversible: every earlier API key is revoked and new keys exist only "
        "as digests. Restore the snapshot taken before the upgrade instead."
    )
