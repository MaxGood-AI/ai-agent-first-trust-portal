"""Team member model — tracks humans, AI agents and client reviewers with API key access.

API keys are never stored: ``api_key_hash`` holds the SHA-256 hex digest of the
key. A key is shown exactly once, when it is issued (``issued_api_key`` is a
transient attribute set by ``team_service`` on the returned object).
"""

import hashlib
import secrets
from datetime import datetime, timezone

from app.models import db

ROLES = ("human", "agent", "client")
WRITER_ROLES = ("human", "agent")


def generate_api_key() -> str:
    """A new random API key (256 bits of entropy, URL-safe)."""
    return secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    """SHA-256 hex digest used to store and look up API keys."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


class TeamMember(db.Model):
    """A human, AI agent or client reviewer with API key access."""
    __tablename__ = "team_members"

    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, comment="human, agent or client")
    api_key_hash = db.Column(db.String(64), unique=True, nullable=True, index=True,
                             comment="SHA-256 hex digest of the API key; NULL = no usable key")
    session_epoch = db.Column(db.Integer, nullable=False, default=0, server_default="0",
                              comment="Incremented on logout; sessions of an earlier epoch are invalid")
    key_rotation_required = db.Column(db.Boolean, default=False, nullable=False,
                                      server_default=db.text("false"),
                                      comment="True until an admin issues this member a new key")
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_compliance_admin = db.Column(db.Boolean, default=False, nullable=False,
                                    comment="Grants access to portal configuration and admin routes")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime(timezone=True))
    company = db.Column(db.String(255))

    # Set only on the object returned when a key is issued; never persisted.
    issued_api_key = None

    @property
    def has_usable_key(self) -> bool:
        return bool(self.api_key_hash)

    @property
    def key_fingerprint(self) -> str:
        """Short, non-secret identifier of the current key (invalidates sessions on rotation)."""
        return (self.api_key_hash or "")[:16]

    @property
    def can_write(self) -> bool:
        return self.role in WRITER_ROLES

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
