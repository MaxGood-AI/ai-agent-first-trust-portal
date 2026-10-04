"""First-admin bootstrap without a shell.

While no active compliance admin holds a usable API key
(``team_service.admin_exists()`` is False) and ``BOOTSTRAP_TOKEN`` is
configured (in the environment or the portal secret), ``/setup`` lets the
operator create an admin by presenting that token. The page shows the new
admin's API key once. While an active, unexpired admin with a usable key
exists, ``/setup`` and ``/api/setup`` return 404; they open again only if no
admin is usable any more (for example when all keys are revoked, or the only
admin's access expired). Every POST consumes one unit of the client IP's
rate-limit budget (``rate_limit.consume``, a single atomic upsert) before the
token is examined and answers 429 once the budget is spent; a successful
setup resets it.

The check and the insert are atomic: on PostgreSQL the request takes the
transaction-scoped admin-membership advisory lock
(``team_service.ADMIN_LOCK_KEY``, also ``BOOTSTRAP_LOCK_KEY``), re-checks
``admin_exists()`` and inserts in the same transaction, so concurrent
requests create at most one admin.

``POST /api/setup`` is the JSON equivalent for automation:
``Authorization: Bearer <BOOTSTRAP_TOKEN>`` with body ``{"name", "email"}``
returns ``201 {"member_id", "api_key"}``. The token header is checked before
the body is read (401 without reading it); a request whose JSON body also
carries a token is refused with 400. The endpoint uses no session and is
exempt from the CSRF check.

Locally, ``python -m cli create-admin`` does the same from a shell.
"""

import hmac
import logging

from flask import Blueprint, abort, current_app, jsonify, render_template, request

from app.models import db
from app.runtime_config import env
from app.security import csrf_exempt
from app.services import rate_limit, team_service

logger = logging.getLogger(__name__)

setup_bp = Blueprint("setup", __name__)

# pg_advisory_xact_lock key serialising first-admin creation (the admin-membership lock).
BOOTSTRAP_LOCK_KEY = team_service.ADMIN_LOCK_KEY
BODY_TOKEN_FIELDS = ("token", "bootstrap_token", "BOOTSTRAP_TOKEN")


def _configured_token():
    return current_app.config.get("BOOTSTRAP_TOKEN") or env("BOOTSTRAP_TOKEN")


def _token_matches(supplied):
    expected = _configured_token()
    if not expected or not supplied:
        return False
    return hmac.compare_digest(expected.encode("utf-8"), supplied.encode("utf-8"))


def _create_first_admin(name, email):
    """Create the admin unless one appeared meanwhile; None when one did."""
    team_service.lock_admin_membership()
    if team_service.admin_exists():
        db.session.rollback()
        return None
    member = team_service.create_member(name, email, "human", is_compliance_admin=True)
    logger.info("Compliance admin created through /setup (member %s)", member.id)
    return member


@setup_bp.route("/setup", methods=["GET", "POST"])
def setup():
    if team_service.admin_exists():
        abort(404)
    token_configured = bool(_configured_token())

    if request.method == "GET":
        return render_template("setup.html", token_configured=token_configured)

    if not rate_limit.consume("setup"):
        return render_template("setup.html", token_configured=token_configured,
                               error="Too many failed attempts. Try again later."), 429

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    if not _token_matches(request.form.get("token", "").strip()):
        return render_template("setup.html", token_configured=token_configured,
                               error="The setup token is not valid."), 401
    if not name or not email:
        return render_template("setup.html", token_configured=token_configured,
                               error="Name and email are required."), 400

    member = _create_first_admin(name, email)
    if member is None:
        abort(404)
    rate_limit.reset("setup")
    return render_template("setup.html", token_configured=token_configured,
                           member=member, api_key=member.issued_api_key)


@setup_bp.route("/api/setup", methods=["POST"])
@csrf_exempt
def api_setup():
    """Create the first compliance admin (bootstrap).
    ---
    tags:
      - Setup
    security:
      - BootstrapToken: []
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [name, email]
            properties:
              name:
                type: string
              email:
                type: string
    responses:
      201:
        description: Admin created; the API key is returned once
      400:
        description: >
          Missing name or email, a token sent in the body as well as the Authorization header,
          or a JSON body nested deeper than 32 levels
      401:
        description: Missing or invalid bootstrap token (checked before the body is read)
      413:
        description: The body is over 1 MiB or its JSON has more than 200,000 values
      404:
        description: An active admin with a usable API key exists (bootstrap closed)
      429:
        description: Too many failed attempts
    """
    if team_service.admin_exists():
        abort(404)
    if not rate_limit.consume("setup"):
        return jsonify({"error": "Too many failed attempts"}), 429
    auth = request.headers.get("Authorization", "")
    supplied = auth[7:].strip() if auth.startswith("Bearer ") else ""
    if not _token_matches(supplied):
        return jsonify({"error": "Invalid bootstrap token: send it in the Authorization header "
                                 "(Authorization: Bearer <token>)"}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    if any(field in data for field in BODY_TOKEN_FIELDS):
        return jsonify({"error": "Send the token in the Authorization header "
                                 "(Authorization: Bearer <token>), not in the body"}), 400
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip()
    if not name or not email:
        return jsonify({"error": "name and email are required"}), 400
    member = _create_first_admin(name, email)
    if member is None:
        abort(404)
    rate_limit.reset("setup")
    return jsonify({"member_id": member.id, "api_key": member.issued_api_key}), 201
