"""Authentication and authorization for the trust portal.

Credentials
-----------
- API clients send their key as ``X-API-Key: <key>`` or
  ``Authorization: Bearer <key>``. Keys are looked up by SHA-256 digest.
  When a request carries either header it is authenticated by that header
  alone: a blank, whitespace-only or unknown key is rejected with 401 and the
  session cookie is never consulted.
- Browser users log in once with their key; the signed session cookie then
  holds only the member id, a fingerprint of the member's current key
  (``TeamMember.key_fingerprint``), the member's session epoch
  (``TeamMember.session_epoch``) and the login time, never the key.
  Regenerating a key, deactivating the member, logging out (which increments
  the member's session epoch, so every session of that member ends, copies of
  the cookie included), or the session reaching ``SESSION_ABSOLUTE_LIFETIME``
  since login (activity does not extend it) ends the session. A login time in
  the future (beyond ``CLOCK_SKEW_SECONDS``) or that is not a number ends it
  too. A session without a recorded epoch belongs to epoch 0; one without a
  login time is bounded from the first request that sees it.
- A ``client`` member starts at most ``AUTH_RATE_LIMIT_ATTEMPTS`` browser
  sessions per ``AUTH_RATE_LIMIT_WINDOW_SECONDS`` window, counted per member
  (``consume_client_session``); each logout is an audited row, so repeated
  sign-ins cannot flood the audit log.

Roles
-----
- ``human`` and ``agent`` members may read and write compliance data.
- ``client`` members (external reviewers) are read-only and default-deny:
  ``require_api_key`` admits them only to the GET endpoints in
  ``CLIENT_ALLOWED_ENDPOINTS`` - the data the client report page shows
  (compliance score and journey, controls list, evidence gaps, systems,
  vendors, approved policies, portal settings) and the report page itself.
  Every other authenticated route answers a client with 403.
- ``is_compliance_admin`` members may use ``/admin`` and admin-only API
  routes (``require_admin``).
"""

import functools
import time

from flask import current_app, g, jsonify, redirect, request, session, url_for

from app.models import db, TeamMember

SESSION_MEMBER_KEY = "member_id"
SESSION_FINGERPRINT_KEY = "key_fp"
SESSION_LOGIN_AT_KEY = "login_at"
SESSION_EPOCH_KEY = "epoch"
# Session keys written by earlier releases; dropped wherever a session is read.
LEGACY_SESSION_KEYS = ("api_key",)
# A login time up to this far in the future is accepted (clock differences between nodes).
CLOCK_SKEW_SECONDS = 300
# Rate-limit bucket counting the browser sessions each client member starts.
CLIENT_SESSION_BUCKET = "client_session"

# Endpoints (Flask endpoint names) a ``client`` member may call, GET only.
CLIENT_ALLOWED_ENDPOINTS = frozenset({
    "api.compliance_score",
    "api.compliance_journey",
    "api.list_controls",
    "api.evidence_gaps",
    "api.get_settings",
    "crud.list_systems",
    "crud.get_systems",
    "crud.list_vendors",
    "crud.get_vendors",
    "crud.list_policies",
    "crud.get_policies",
    "admin.client_report",
})
CLIENT_ALLOWED_METHODS = frozenset({"GET", "HEAD"})


def login_session(member: TeamMember) -> None:
    """Start a fresh browser session for ``member`` (prevents session fixation)."""
    session.clear()
    session.permanent = True
    session[SESSION_MEMBER_KEY] = member.id
    session[SESSION_FINGERPRINT_KEY] = member.key_fingerprint
    session[SESSION_EPOCH_KEY] = member.session_epoch or 0
    session[SESSION_LOGIN_AT_KEY] = int(time.time())


def consume_client_session(member: TeamMember) -> bool:
    """Count one browser session started by the client ``member``; True while within its budget.

    Logging out writes an audited row (the session-epoch bump), so a client
    member may start at most ``AUTH_RATE_LIMIT_ATTEMPTS`` sessions per
    ``AUTH_RATE_LIMIT_WINDOW_SECONDS`` window (defaults 10 per 15 minutes).
    The budget is counted per member, whatever the client IP, in the shared
    ``auth_rate_limit`` table (bucket ``client_session``, key
    ``member:<id>``) through one atomic upsert, and a successful sign-in does
    not clear it.
    """
    from app.models.auth_rate_limit import AuthRateLimitWindow
    from app.services import rate_limit

    statement = rate_limit._upsert()(AuthRateLimitWindow).values(
        bucket=CLIENT_SESSION_BUCKET, client_key=f"member:{member.id}",
        window_start=rate_limit._window_start(), attempts=1)
    statement = statement.on_conflict_do_update(
        index_elements=["bucket", "client_key", "window_start"],
        set_={"attempts": AuthRateLimitWindow.attempts + 1},
    ).returning(AuthRateLimitWindow.attempts)
    attempts = db.session.execute(statement).scalar()
    db.session.commit()
    return attempts <= rate_limit._limit()


def logout_session() -> None:
    """End this browser session and revoke every session of its member.

    When the session is valid, the member's ``session_epoch`` is incremented
    (an audited change attributed to the member), so every cookie issued
    before, including copies of this one, is rejected from now on.
    """
    member = _session_member()
    session.clear()
    if member is not None:
        g.current_team_member = member
        member.session_epoch = TeamMember.session_epoch + 1
        db.session.commit()


def drop_legacy_session_keys() -> None:
    """Remove keys that earlier releases stored in the session cookie."""
    for key in LEGACY_SESSION_KEYS:
        if key in session:
            session.pop(key)


def api_key_header():
    """The API key the request presents in a header, or None when it presents none.

    ``X-API-Key`` takes precedence over ``Authorization: Bearer`` (scheme
    matched case-insensitively). A header that is present but blank or
    whitespace-only yields ``""``, which authenticates nobody.
    """
    if "X-API-Key" in request.headers:
        return request.headers.get("X-API-Key", "").strip()
    auth = request.headers.get("Authorization", "")
    parts = auth.strip().split(None, 1)
    if parts and parts[0].lower() == "bearer":
        return parts[1].strip() if len(parts) > 1 else ""
    return None


def header_member():
    """The active member whose key the request's API-key header carries, or None."""
    from app.services.team_service import find_by_api_key

    key = api_key_header()
    return find_by_api_key(key) if key else None


def _session_expired() -> bool:
    """True once the session is older than ``SESSION_ABSOLUTE_LIFETIME``, or
    when its login time is not a number or lies in the future.

    A session without a recorded login time gets one now, so its lifetime is
    bounded from the first request that sees it.
    """
    now = time.time()
    if SESSION_LOGIN_AT_KEY not in session:
        session[SESSION_LOGIN_AT_KEY] = int(now)
        return False
    login_at = session.get(SESSION_LOGIN_AT_KEY)
    if isinstance(login_at, bool) or not isinstance(login_at, (int, float)):
        return True
    if login_at > now + CLOCK_SKEW_SECONDS:
        return True
    lifetime = current_app.config["SESSION_ABSOLUTE_LIFETIME"]
    return now - login_at > lifetime.total_seconds()


def _epoch_matches(member: TeamMember) -> bool:
    epoch = session.get(SESSION_EPOCH_KEY, 0)
    return not isinstance(epoch, bool) and epoch == (member.session_epoch or 0)


def _session_member():
    drop_legacy_session_keys()
    member_id = session.get(SESSION_MEMBER_KEY)
    if not member_id:
        return None
    member = db.session.get(TeamMember, member_id)
    if (
        member is None
        or not member.is_active
        or not member.has_usable_key
        or session.get(SESSION_FINGERPRINT_KEY) != member.key_fingerprint
        or not _epoch_matches(member)
        or _session_expired()
    ):
        session.clear()
        return None
    return member


def current_member():
    """Resolve the member for this request: ``(member, via_header)``.

    A request with an API-key header is authenticated by that header only.
    """
    if api_key_header() is not None:
        return header_member(), True
    return _session_member(), False


def _is_browser_request():
    """Check if the request looks like it came from a browser."""
    return "text/html" in request.headers.get("Accept", "")


def _login_redirect(error=None):
    return redirect(url_for("admin.login", next=request.path, error=error))


def client_may_access() -> bool:
    """True when the current request is one a ``client`` member may make."""
    return request.method in CLIENT_ALLOWED_METHODS and request.endpoint in CLIENT_ALLOWED_ENDPOINTS


def require_api_key(f):
    """Decorator requiring an authenticated, active, unexpired team member.

    ``client`` members are further limited to ``CLIENT_ALLOWED_ENDPOINTS``.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        member, via_header = current_member()
        if member is None:
            if _is_browser_request() and not via_header:
                return _login_redirect()
            if via_header:
                return jsonify({"error": "Invalid or inactive API key"}), 401
            return jsonify({"error": "Missing API key"}), 401

        if member.is_expired:
            if _is_browser_request():
                session.clear()
                return redirect(url_for("admin.client_login", error="expired"))
            return jsonify({"error": "API key has expired"}), 401

        if member.role == "client" and not client_may_access():
            if _is_browser_request() and not request.path.startswith("/api/"):
                return _login_redirect("forbidden")
            return jsonify({"error": "Client access is limited to the compliance report"}), 403

        g.current_team_member = member
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Decorator requiring a compliance admin. Must follow @require_api_key."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        member = getattr(g, "current_team_member", None)
        if not member or not member.is_compliance_admin:
            if _is_browser_request():
                return _login_redirect("forbidden")
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


def require_writer(f):
    """Decorator rejecting read-only (client) members. Must follow @require_api_key."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        member = getattr(g, "current_team_member", None)
        if not member or not member.can_write:
            return jsonify({"error": "Read-only access: this key cannot modify compliance data"}), 403
        return f(*args, **kwargs)
    return decorated


def require_team(f):
    """Decorator limiting a route to team members (human/agent), not clients."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        member = getattr(g, "current_team_member", None)
        if not member or member.role == "client":
            return jsonify({"error": "Team members only"}), 403
        return f(*args, **kwargs)
    return decorated


def require_client_or_admin(f):
    """Allow access for client, human, or agent roles. Must follow @require_api_key."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        member = g.current_team_member
        if member.role not in ("human", "agent", "client"):
            if _is_browser_request():
                return redirect(url_for("admin.client_login", error="forbidden"))
            return jsonify({"error": "Insufficient permissions"}), 403
        return f(*args, **kwargs)
    return decorated


def current_member_is_client() -> bool:
    """True when the authenticated member of this request is a ``client``."""
    member = getattr(g, "current_team_member", None)
    return member is not None and member.role == "client"
