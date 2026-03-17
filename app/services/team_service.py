"""Team member CRUD operations."""

import secrets
import uuid

from app.models import db, TeamMember


def create_member(name, email, role, is_compliance_admin=False):
    """Create a new team member with a generated API key."""
    member = TeamMember(
        id=str(uuid.uuid4()),
        name=name,
        email=email,
        role=role,
        is_compliance_admin=is_compliance_admin,
    )
    db.session.add(member)
    db.session.commit()
    return member


def list_members(include_inactive=False):
    """List all team members."""
    query = TeamMember.query
    if not include_inactive:
        query = query.filter_by(is_active=True)
    return query.order_by(TeamMember.name).all()


def deactivate_member(member_id):
    """Deactivate a team member."""
    member = TeamMember.query.get(member_id)
    if not member:
        return None
    member.is_active = False
    db.session.commit()
    return member


def regenerate_key(member_id):
    """Generate a new API key for a team member."""
    member = TeamMember.query.get(member_id)
    if not member:
        return None
    member.api_key = secrets.token_urlsafe(32)
    db.session.commit()
    return member
