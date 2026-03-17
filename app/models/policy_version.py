"""Policy version model — tracks CLAUDE.md and AGENTS.md as formal policy versions."""

from datetime import datetime, timezone

from app.models import db


class PolicyVersion(db.Model):
    """A versioned snapshot of a governance file (CLAUDE.md, AGENTS.md)."""
    __tablename__ = "policy_versions"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_path = db.Column(db.String(500), nullable=False, comment="Relative path from ~/Development")
    repo = db.Column(db.String(100), nullable=False, comment="Repository name")
    git_commit = db.Column(db.String(40), nullable=False, comment="Commit SHA where this version was introduced")
    git_author = db.Column(db.String(255))
    commit_message = db.Column(db.Text)
    content_hash = db.Column(db.String(64), comment="SHA-256 of file content for dedup")
    effective_at = db.Column(db.DateTime, comment="Commit timestamp — when this version took effect")
    imported_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<PolicyVersion {self.file_path} @ {self.git_commit[:8]}>"
