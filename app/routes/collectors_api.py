"""API routes for evidence collector configuration and management.

All endpoints require admin authentication. Credentials are never returned
from any endpoint (not even masked). Credential updates are logged to the
audit trail via the existing PostgreSQL audit triggers on the
collector_config table.
"""

import uuid
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request

from app.auth import require_admin, require_api_key
from app.models import db
from app.models.collector_config import CollectorConfig
from app.models.collector_run import CollectorRun
from app.services.collector_encryption import (
    CollectorEncryptionError,
    encrypt_credentials,
)
from app.services.collector_executor import execute_run
from app.services.credential_resolver import (
    CredentialResolutionError,
    CredentialResolver,
    SUPPORTED_MODES,
)
from app.services.permission_prober import PermissionProber
from collectors.registry import get_collector_class

collectors_api_bp = Blueprint("collectors_api", __name__)


KNOWN_COLLECTOR_NAMES = {"aws", "git", "platform", "policy", "vendor"}


def _serialize_config(config: CollectorConfig) -> dict:
    """Serialize a CollectorConfig for API responses. Never includes credentials."""
    return {
        "id": config.id,
        "name": config.name,
        "enabled": config.enabled,
        "credential_mode": config.credential_mode,
        "has_stored_credentials": config.encrypted_credentials is not None,
        "config": config.config or {},
        "schedule_cron": config.schedule_cron,
        "last_run_at": config.last_run_at.isoformat() if config.last_run_at else None,
        "next_run_at": config.next_run_at.isoformat() if config.next_run_at else None,
        "last_run_status": config.last_run_status,
        "permission_check_at": (
            config.permission_check_at.isoformat() if config.permission_check_at else None
        ),
        "permission_check_result": config.permission_check_result,
        "created_at": config.created_at.isoformat() if config.created_at else None,
        "updated_at": config.updated_at.isoformat() if config.updated_at else None,
    }


def _serialize_run(run: CollectorRun) -> dict:
    return {
        "id": run.id,
        "collector_config_id": run.collector_config_id,
        "triggered_by_team_member_id": run.triggered_by_team_member_id,
        "trigger_type": run.trigger_type,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "status": run.status,
        "evidence_count": run.evidence_count,
        "check_pass_count": run.check_pass_count,
        "check_fail_count": run.check_fail_count,
        "error_message": run.error_message,
    }


@collectors_api_bp.route("/collectors/environment", methods=["GET"])
@require_api_key
@require_admin
def detect_environment():
    """Detect the running environment (ECS/EC2/other) and current AWS identity.

    Used by the setup wizard to pre-fill sensible defaults.
    ---
    responses:
      200:
        description: Environment detection result
    """
    import os

    env_info = {
        "is_ecs": bool(os.environ.get("ECS_CONTAINER_METADATA_URI_V4")),
        "is_ec2": False,  # probed below
        "default_region": os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
        "identity": None,
        "account_id": None,
    }

    try:
        import boto3

        session = boto3.Session()
        sts = session.client("sts")
        caller = sts.get_caller_identity()
        env_info["identity"] = caller.get("Arn")
        env_info["account_id"] = caller.get("Account")
        env_info["default_region"] = env_info["default_region"] or session.region_name
    except Exception as exc:  # noqa: BLE001
        env_info["error"] = str(exc)

    return jsonify(env_info), 200


@collectors_api_bp.route("/collectors", methods=["GET"])
@require_api_key
@require_admin
def list_collectors():
    """List all configured collectors.
    ---
    responses:
      200:
        description: List of collector configs
    """
    configs = CollectorConfig.query.order_by(CollectorConfig.name).all()
    return jsonify([_serialize_config(c) for c in configs]), 200


@collectors_api_bp.route("/collectors/<name>", methods=["GET"])
@require_api_key
@require_admin
def get_collector(name):
    """Get a single collector config by name (credentials never returned).
    ---
    parameters:
      - name: name
        in: path
        type: string
        required: true
    responses:
      200:
        description: Collector config
      404:
        description: Not found
    """
    config = CollectorConfig.query.filter_by(name=name).first()
    if not config:
        return jsonify({"error": f"No collector named {name}"}), 404
    return jsonify(_serialize_config(config)), 200


@collectors_api_bp.route("/collectors/<name>/configure", methods=["POST"])
@require_api_key
@require_admin
def configure_collector(name):
    """Create or update a collector config.

    Request body:
        {
          "credential_mode": "task_role | task_role_assume | access_keys | none",
          "credentials": { ... },       # optional, mode-dependent
          "config": { ... },            # optional, non-secret config
          "schedule_cron": "0 6 * * 1", # optional
          "enabled": true               # optional, default false
        }
    ---
    responses:
      200:
        description: Updated config
      400:
        description: Validation error
    """
    if name not in KNOWN_COLLECTOR_NAMES:
        return jsonify({"error": f"Unknown collector: {name}"}), 400

    data = request.get_json() or {}
    credential_mode = data.get("credential_mode", "task_role")
    if credential_mode not in SUPPORTED_MODES:
        return jsonify({"error": f"Invalid credential_mode: {credential_mode}"}), 400

    config = CollectorConfig.query.filter_by(name=name).first()
    if not config:
        config = CollectorConfig(id=str(uuid.uuid4()), name=name)
        db.session.add(config)

    config.credential_mode = credential_mode
    if "config" in data:
        config.config = data["config"]
    if "schedule_cron" in data:
        config.schedule_cron = data["schedule_cron"]
    if "enabled" in data:
        config.enabled = bool(data["enabled"])

    # Handle credentials: only encrypt and store if provided.
    credentials = data.get("credentials")
    if credentials is not None:
        if credential_mode in ("task_role", "none"):
            # No credentials stored in these modes; clear any existing ciphertext.
            config.encrypted_credentials = None
        else:
            try:
                config.encrypted_credentials = encrypt_credentials(credentials)
            except CollectorEncryptionError as exc:
                return jsonify({"error": str(exc)}), 400

    member = getattr(g, "current_team_member", None)
    if member:
        if not config.created_by_id:
            config.created_by_id = member.id
        config.updated_by_id = member.id

    db.session.commit()
    return jsonify(_serialize_config(config)), 200


@collectors_api_bp.route("/collectors/<name>/test-connection", methods=["POST"])
@require_api_key
@require_admin
def test_connection(name):
    """Resolve credentials and run a minimal connection test (e.g., sts:GetCallerIdentity).
    ---
    responses:
      200:
        description: Connection result
      404:
        description: Collector not configured
    """
    config = CollectorConfig.query.filter_by(name=name).first()
    if not config:
        return jsonify({"error": f"No collector named {name}"}), 404

    resolver = CredentialResolver()
    try:
        resolved = resolver.resolve(config)
    except CredentialResolutionError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 200

    prober = PermissionProber()
    result = prober.probe(resolved, required_actions=[])
    return jsonify({"ok": result.all_passed, "probe": result.to_dict()}), 200


@collectors_api_bp.route("/collectors/<name>/probe", methods=["POST"])
@require_api_key
@require_admin
def probe_collector(name):
    """Run the full permission probe for the collector and cache the result.

    If a collector class is registered for this name, the probe uses the
    collector's declared ``required_permissions`` list. Callers may override
    by passing ``required_actions`` in the request body.
    ---
    responses:
      200:
        description: Probe result
      404:
        description: Collector not configured
    """
    config = CollectorConfig.query.filter_by(name=name).first()
    if not config:
        return jsonify({"error": f"No collector named {name}"}), 404

    resolver = CredentialResolver()
    try:
        resolved = resolver.resolve(config)
    except CredentialResolutionError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 200

    body = request.get_json() or {}
    required_actions = body.get("required_actions")
    if required_actions is None:
        collector_cls = get_collector_class(name)
        required_actions = list(collector_cls.required_permissions) if collector_cls else []

    prober = PermissionProber()
    result = prober.probe(resolved, required_actions=required_actions)

    config.permission_check_at = datetime.now(timezone.utc)
    config.permission_check_result = result.to_dict()
    db.session.commit()

    return jsonify({"ok": result.all_passed, "probe": result.to_dict()}), 200


@collectors_api_bp.route("/collectors/<name>/required-policy", methods=["GET"])
@require_api_key
@require_admin
def collector_required_policy(name):
    """Return the AWS IAM policy JSON that grants this collector's required actions.

    Reads from ``iam/trust-portal-collector-policy.json`` if present; falls
    back to a policy generated from the collector's declared permissions.
    ---
    responses:
      200:
        description: IAM policy document
      404:
        description: Collector not registered
    """
    import json
    import os

    collector_cls = get_collector_class(name)
    if collector_cls is None:
        return jsonify({"error": f"No collector registered for name {name}"}), 404

    repo_root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    policy_path = os.path.join(repo_root, "iam", "trust-portal-collector-policy.json")
    if os.path.exists(policy_path):
        with open(policy_path) as f:
            policy = json.load(f)
    else:
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "TrustPortalCollectorReadOnly",
                    "Effect": "Allow",
                    "Action": list(collector_cls.required_permissions),
                    "Resource": "*",
                }
            ],
        }

    return jsonify({
        "collector": name,
        "required_permissions": list(collector_cls.required_permissions),
        "policy": policy,
    }), 200


@collectors_api_bp.route("/collectors/<name>/enable", methods=["POST"])
@require_api_key
@require_admin
def enable_collector(name):
    """Enable or disable a collector.
    ---
    responses:
      200:
        description: Updated config
    """
    config = CollectorConfig.query.filter_by(name=name).first()
    if not config:
        return jsonify({"error": f"No collector named {name}"}), 404
    data = request.get_json() or {}
    config.enabled = bool(data.get("enabled", True))
    member = getattr(g, "current_team_member", None)
    if member:
        config.updated_by_id = member.id
    db.session.commit()
    return jsonify(_serialize_config(config)), 200


@collectors_api_bp.route("/collectors/<name>/runs", methods=["GET"])
@require_api_key
@require_admin
def list_runs(name):
    """List recent runs for a collector.
    ---
    responses:
      200:
        description: List of runs
    """
    config = CollectorConfig.query.filter_by(name=name).first()
    if not config:
        return jsonify({"error": f"No collector named {name}"}), 404
    runs = (
        CollectorRun.query
        .filter_by(collector_config_id=config.id)
        .order_by(CollectorRun.started_at.desc())
        .limit(100)
        .all()
    )
    return jsonify([_serialize_run(r) for r in runs]), 200


@collectors_api_bp.route("/collectors/runs/<run_id>", methods=["GET"])
@require_api_key
@require_admin
def get_run(run_id):
    """Get a single run with its check results.
    ---
    responses:
      200:
        description: Run detail
      404:
        description: Run not found
    """
    run = db.session.get(CollectorRun, run_id)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    checks = run.check_results.all()
    return jsonify({
        "run": _serialize_run(run),
        "checks": [
            {
                "id": c.id,
                "check_name": c.check_name,
                "target_test_id": c.target_test_id,
                "status": c.status,
                "evidence_id": c.evidence_id,
                "message": c.message,
                "detail": c.detail,
            }
            for c in checks
        ],
    }), 200


@collectors_api_bp.route("/collectors/<name>/run", methods=["POST"])
@require_api_key
@require_admin
def run_collector(name):
    """Trigger an immediate collector run and execute it synchronously.

    Creates a CollectorRun row, resolves credentials, runs the registered
    collector class, writes per-check results and evidence to the database,
    and returns the final run state.
    ---
    responses:
      200:
        description: Run completed (success, partial, or failure)
      404:
        description: Collector not configured or not registered
    """
    config = CollectorConfig.query.filter_by(name=name).first()
    if not config:
        return jsonify({"error": f"No collector named {name}"}), 404

    collector_cls = get_collector_class(name)
    if collector_cls is None:
        return jsonify({"error": f"No collector class registered for {name}"}), 404

    member = getattr(g, "current_team_member", None)
    run = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        triggered_by_team_member_id=member.id if member else None,
        trigger_type="manual",
        status="running",
    )
    db.session.add(run)
    db.session.commit()

    execute_run(run)

    return jsonify(_serialize_run(run)), 200
