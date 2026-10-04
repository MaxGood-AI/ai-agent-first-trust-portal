"""Team member CRUD operations.

API keys are generated here and stored only as SHA-256 digests. The plaintext
key is returned once, on the ``issued_api_key`` attribute of the member
object that ``create_member`` / ``regenerate_key`` return.

A *usable admin* is an active, unexpired compliance admin holding an API key;
a *durable admin* is a usable admin without an expiry or whose expiry is more
than ``DURABLE_ADMIN_MARGIN`` (30 days) away. The portal always keeps a
durable admin: ``deactivate_member`` refuses (``LastAdminError``) to
deactivate a usable admin unless another durable admin remains, so an admin
whose access ends soon never counts as the replacement of one whose access
does not. Changes to admin membership (first-admin
bootstrap, deactivation) take the transaction-scoped PostgreSQL advisory lock
``ADMIN_LOCK_KEY`` before they read the admins, so concurrent requests cannot
together remove every usable admin or create two first admins.
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.models import db, TeamMember
from app.models.team_member import ROLES, generate_api_key, hash_api_key

# pg_advisory_xact_lock key serialising changes to admin membership.
ADMIN_LOCK_KEY = 815000100
# An admin whose access ends within this margin does not keep the portal administrable.
DURABLE_ADMIN_MARGIN = timedelta(days=30)


class LastAdminError(ValueError):
    """The change would leave the portal without a usable compliance admin."""


def create_member(name, email, role, is_compliance_admin=False, company=None, expires_at=None):
    """Create a new team member and issue its API key (returned once)."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    api_key = generate_api_key()
    member = TeamMember(
        id=str(uuid.uuid4()),
        name=name,
        email=email,
        role=role,
        api_key_hash=hash_api_key(api_key),
        is_compliance_admin=is_compliance_admin,
        company=company,
        expires_at=expires_at,
    )
    db.session.add(member)
    db.session.commit()
    member.issued_api_key = api_key
    return member


def find_by_api_key(api_key):
    """Return the active member holding ``api_key``, or None."""
    if not api_key:
        return None
    return TeamMember.query.filter_by(api_key_hash=hash_api_key(api_key), is_active=True).first()


def list_members(include_inactive=False):
    """List all team members."""
    query = TeamMember.query
    if not include_inactive:
        query = query.filter_by(is_active=True)
    return query.order_by(TeamMember.name).all()


def lock_admin_membership():
    """Serialise admin-membership changes until the current transaction ends
    (PostgreSQL; a no-op on other databases)."""
    if db.engine.dialect.name == "postgresql":
        db.session.execute(db.text("SELECT pg_advisory_xact_lock(:k)"), {"k": ADMIN_LOCK_KEY})


def is_usable_admin(member):
    """True for an active, unexpired compliance admin holding an API key."""
    return bool(member.is_compliance_admin and member.is_active and member.has_usable_key
                and not member.is_expired)


def is_durable_admin(member, now=None):
    """True for a usable admin without an expiry or whose expiry is beyond DURABLE_ADMIN_MARGIN."""
    if not is_usable_admin(member):
        return False
    expires = member.expires_at
    if expires is None:
        return True
    if expires.tzinfo is None:  # SQLite returns naive datetimes
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > (now or datetime.now(timezone.utc)) + DURABLE_ADMIN_MARGIN


def usable_admins():
    """Every usable admin, read fresh from the database."""
    candidates = TeamMember.query.filter(
        TeamMember.is_compliance_admin.is_(True),
        TeamMember.is_active.is_(True),
        TeamMember.api_key_hash.isnot(None),
    ).execution_options(populate_existing=True).all()
    return [member for member in candidates if not member.is_expired]


def admin_exists():
    """True while a usable admin exists (active, unexpired, holding an API key).

    ``/setup`` accepts the bootstrap token only while this is False: on a new
    portal, after every key was revoked (migration 017) until an admin holds
    a new one, and when every admin's access expired.
    """
    return bool(usable_admins())


def deactivate_member(member_id):
    """Deactivate a team member; None when there is no such member.

    Raises ``LastAdminError`` (nothing changed) when the member is a usable
    admin and no other durable admin (no expiry, or an expiry more than 30 days
    away) would remain.
    """
    lock_admin_membership()
    member = db.session.get(TeamMember, member_id, populate_existing=True)
    if not member:
        db.session.rollback()
        return None
    if is_usable_admin(member) and not any(
            other.id != member.id and is_durable_admin(other) for other in usable_admins()):
        message = (f"{member.name} cannot be deactivated: the portal keeps its last active compliance "
                   "admin, and no other admin with a usable API key and no expiry (or an expiry more "
                   "than 30 days away) would remain. Add or re-key such an admin first.")
        db.session.rollback()
        raise LastAdminError(message)
    member.is_active = False
    db.session.commit()
    return member


def regenerate_key(member_id):
    """Issue a new API key for a team member (returned once); the old key stops working."""
    member = db.session.get(TeamMember, member_id)
    if not member:
        return None
    api_key = generate_api_key()
    member.api_key_hash = hash_api_key(api_key)
    member.key_rotation_required = False
    db.session.commit()
    member.issued_api_key = api_key
    return member


def find_member(identifier):
    """Look a member up by id or (case-insensitive) email; None when absent or ambiguous."""
    member = db.session.get(TeamMember, identifier)
    if member is not None:
        return member
    matches = TeamMember.query.filter(db.func.lower(TeamMember.email) == identifier.lower()).all()
    return matches[0] if len(matches) == 1 else None
