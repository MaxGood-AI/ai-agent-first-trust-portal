"""Decision log model — stores AI agent session interactions for compliance audit trail."""

from datetime import datetime, timezone

from app.models import db


class DecisionLogSession(db.Model):
    """A single AI agent session (e.g., one Claude Code conversation)."""
    __tablename__ = "decision_log_sessions"

    id = db.Column(db.String(36), primary_key=True, comment="Claude Code session ID")
    agent_type = db.Column(db.String(50), default="claude_code", comment="claude_code, codex, etc.")
    model = db.Column(db.String(100), comment="Model used, e.g. claude-opus-4-6")
    cwd = db.Column(db.String(500), comment="Working directory at session start")
    git_branch = db.Column(db.String(200), comment="Git branch at session start")
    started_at = db.Column(db.DateTime)
    ended_at = db.Column(db.DateTime)
    exit_reason = db.Column(db.String(50))
    transcript_path = db.Column(db.String(500), comment="Path to original JSONL file")
    submitted_by = db.Column(db.String(36), db.ForeignKey("team_members.id"), nullable=True,
                             comment="Team member who submitted this transcript")
    imported_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    content_sha256 = db.Column(db.String(64), comment="SHA-256 of the stored transcript bytes")
    content_bytes = db.Column(db.BigInteger, comment="Size in bytes of the stored transcript")
    replaced_at = db.Column(db.DateTime(timezone=True),
                            comment="When a longer export last replaced the stored transcript")
    repository_entries = db.Column(
        db.Integer, comment="Leading stored entries supplied by the evidence repository (NULL: not recorded)")
    conflict_at = db.Column(
        db.DateTime(timezone=True),
        comment="When a repository version last replaced entries submitted through the API")
    conflict_detail = db.Column(db.Text, comment="What the last conflict replaced")

    # Entries in transcript (insertion) order; timestamps never reorder them.
    interactions = db.relationship("DecisionLogEntry", backref="session", lazy="dynamic",
                                   order_by="DecisionLogEntry.id")

    def __repr__(self):
        return f"<DecisionLogSession {self.id} ({self.agent_type})>"


class DecisionLogEntry(db.Model):
    """A single interaction (prompt or response) within a session."""
    __tablename__ = "decision_log_entries"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Deferrable, so an import can write a new session's entries before its audited session row.
    session_id = db.Column(db.String(36), db.ForeignKey(
        "decision_log_sessions.id", name="fk_decision_log_entries_session", deferrable=True,
        initially="IMMEDIATE"), nullable=False)
    role = db.Column(db.String(20), nullable=False, comment="user or assistant")
    content_text = db.Column(db.Text, comment="Text content of the message")
    tool_calls = db.Column(db.Text, comment="JSON array of tool calls, if any")
    timestamp = db.Column(db.DateTime)
    message_id = db.Column(db.String(100), comment="Original message ID from transcript")
    is_verification = db.Column(
        db.Boolean, default=False,
        comment="True if this is a 'done.' verification acknowledgment"
    )

    def __repr__(self):
        return f"<DecisionLogEntry {self.role} in {self.session_id}>"


class DecisionLogTranscript(db.Model):
    """One received version of a session's transcript.

    ``current``: the version the entries were parsed from. ``superseded``: an
    earlier version replaced by a longer export that extends it, or by the
    evidence repository's version in a conflict (its content is kept,
    gzipped). ``rejected``: an upload that does not extend the stored
    transcript (kept, gzipped, for review; the stored transcript is
    unchanged). ``entry_count`` and ``entries_sha256`` describe the version's
    entries (``app.services.evidence_import_decision_logs.entries_digest``).
    """
    __tablename__ = "decision_log_transcripts"

    id = db.Column(db.String(36), primary_key=True)
    session_id = db.Column(db.String(36), db.ForeignKey("decision_log_sessions.id"), nullable=False)
    status = db.Column(db.String(16), nullable=False, comment="current | superseded | rejected")
    content_sha256 = db.Column(db.String(64))
    content_bytes = db.Column(db.BigInteger)
    entry_count = db.Column(db.Integer, nullable=False, default=0)
    entries_sha256 = db.Column(db.String(64), comment="Digest of the version's entries")
    content_gz = db.Column(db.LargeBinary)
    reason = db.Column(db.Text)
    source_path = db.Column(db.String(500))
    source_commit = db.Column(db.String(64), comment="Evidence-repository commit a git sync read it at")
    submitted_by = db.Column(db.String(36), db.ForeignKey("team_members.id"))
    received_at = db.Column(db.DateTime(timezone=True), nullable=False,
                            default=lambda: datetime.now(timezone.utc))

    __table_args__ = (db.Index("ix_decision_log_transcripts_session", "session_id", "received_at"),)
