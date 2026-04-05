"""Team member model — tracks humans and AI agents with API key authentication."""

import secrets
from datetime import datetime, timezone

from app.models import db


def _generate_api_key():
    return secrets.token_urlsafe(32)


class TeamMember(db.Model):
    """A human or AI agent team member with API key access."""
    __tablename__ = "team_members"

    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, comment="human or agent")
    api_key = db.Column(db.String(64), unique=True, nullable=False, index=True,
                        default=_generate_api_key)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_compliance_admin = db.Column(db.Boolean, default=False, nullable=False,
                                    comment="Grants access to portal configuration and admin routes")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime(timezone=True))
    company = db.Column(db.String(255))

    @property
    def is_expired(self):
        if not self.expires_at:
            return False
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        # Handle naive datetimes from SQLite (test environment)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now > expires

    def __repr__(self):
        return f"<TeamMember {self.name} ({self.role})>"
