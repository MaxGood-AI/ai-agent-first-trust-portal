"""API key authentication for the trust portal."""

import functools

from flask import request, g, jsonify, redirect, url_for, session

from app.models import db, TeamMember


def _extract_api_key():
    """Extract API key from X-API-Key header, Authorization Bearer, or session."""
    key = request.headers.get("X-API-Key")
    if key:
        return key
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return session.get("api_key")


def _is_browser_request():
    """Check if the request looks like it came from a browser."""
    accept = request.headers.get("Accept", "")
    return "text/html" in accept


def require_api_key(f):
    """Decorator requiring a valid API key on the request."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        api_key = _extract_api_key()
        if not api_key:
            if _is_browser_request():
                return redirect(url_for("admin.login", next=request.path))
            return jsonify({"error": "Missing API key"}), 401

        member = TeamMember.query.filter_by(api_key=api_key, is_active=True).first()
        if not member:
            if _is_browser_request():
                return redirect(url_for("admin.login", next=request.path, error="invalid"))
            return jsonify({"error": "Invalid or inactive API key"}), 401

        g.current_team_member = member
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Decorator requiring the authenticated team member to be a compliance admin.

    Must be used after @require_api_key.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        member = getattr(g, "current_team_member", None)
        if not member or not member.is_compliance_admin:
            if _is_browser_request():
                return redirect(url_for("admin.login", next=request.path, error="forbidden"))
            return jsonify({"error": "Admin access required"}), 403

        return f(*args, **kwargs)
    return decorated
