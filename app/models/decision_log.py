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

    interactions = db.relationship("DecisionLogEntry", backref="session", lazy="dynamic",
                                   order_by="DecisionLogEntry.timestamp")

    def __repr__(self):
        return f"<DecisionLogSession {self.id} ({self.agent_type})>"


class DecisionLogEntry(db.Model):
    """A single interaction (prompt or response) within a session."""
    __tablename__ = "decision_log_entries"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_id = db.Column(db.String(36), db.ForeignKey("decision_log_sessions.id"), nullable=False)
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
