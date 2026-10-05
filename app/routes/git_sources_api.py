"""API routes for git sources (governance and evidence repositories).

Every route is admin-only. ``<source>`` is a source id or its unique name.
Syncs are asynchronous: ``POST .../sync`` queues a run and returns its id
and ``poll_url``; the scheduler leader executes it.
"""

from flask import Blueprint, g, jsonify, request

from app.auth import require_admin, require_api_key
from app.models import db
from app.models.git_source import GitSource, GitSyncRun
from app.services.git_sources.service import (
    GitSourceConfigError,
    create_source,
    find_source,
    serialize_run,
    serialize_source,
    set_last_synced_commit,
    update_source,
)
from app.services.scheduler import ActiveRunConflict, enqueue_git_sync

git_sources_api_bp = Blueprint("git_sources_api", __name__)


def _member_id():
    member = getattr(g, "current_team_member", None)
    return member.id if member else None


def _source_or_404(identifier):
    source = find_source(identifier)
    if source is None:
        return None, (jsonify({"error": f"No git source {identifier!r}"}), 404)
    return source, None


@git_sources_api_bp.route("/git-sources", methods=["GET"])
@require_api_key
@require_admin
def list_git_sources():
    """List git sources.
    ---
    tags:
      - Git sources
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: Configured git sources (credentials are never returned)
    """
    sources = GitSource.query.order_by(GitSource.name).all()
    return jsonify([serialize_source(s) for s in sources])


@git_sources_api_bp.route("/git-sources", methods=["POST"])
@require_api_key
@require_admin
def create_git_source():
    """Create a git source.
    ---
    tags:
      - Git sources
    security:
      - ApiKeyAuth: []
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [name, role, provider, repository]
            properties:
              name: {type: string}
              role: {type: string, enum: [governance, evidence]}
              provider: {type: string, enum: [codecommit, github, local]}
              repository:
                type: string
                description: >
                  CodeCommit repo name, GitHub owner/name, or local directory (an absolute path
                  inside LOCAL_SOURCE_ROOTS when that is set; local sources need it in production)
              branch: {type: string, default: main}
              region: {type: string, description: "AWS region (CodeCommit); defaults to AWS_REGION"}
              credential_mode:
                type: string
                description: "codecommit: runtime_role | assume_role; github: portal_secret | stored_token | none; local: none"
              credentials:
                type: object
                description: "{role_arn, external_id} for assume_role, {token} for stored_token; write-only"
              schedule_cron: {type: string, description: "5-field crontab, UTC, 0 = Sunday"}
              enabled: {type: boolean, default: true}
              path_mappings:
                type: array
                nullable: true
                description: >-
                  Replaces the role's default mappings (null: the defaults; an evidence source's
                  defaults map every kind of the evidence repository layout). An evidence source
                  whose repository leaves pentest evidence and decision logs to the evidence store
                  maps only the six authored datasets.
                items:
                  type: object
                  properties:
                    pattern: {type: string}
                    kind: {type: string}
              options:
                type: object
                properties:
                  record_commits: {type: boolean}
                  history_limit: {type: integer}
                  api_url:
                    type: string
                    description: >
                      GitHub Enterprise Server API URL (https). Any value other than
                      https://api.github.com requires credential_mode stored_token or none.
    responses:
      201:
        description: Created source
      400:
        description: Validation error
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object body required"}), 400
    try:
        source = create_source(data, member_id=_member_id())
    except GitSourceConfigError as exc:
        db.session.rollback()
        return jsonify({"error": str(exc)}), 400
    return jsonify(serialize_source(source)), 201


@git_sources_api_bp.route("/git-sources/<source_ref>", methods=["GET"])
@require_api_key
@require_admin
def get_git_source(source_ref):
    """Get one git source.
    ---
    tags:
      - Git sources
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: The source
      404:
        description: Not found
    """
    source, error = _source_or_404(source_ref)
    if error:
        return error
    return jsonify(serialize_source(source))


@git_sources_api_bp.route("/git-sources/<source_ref>", methods=["PUT"])
@require_api_key
@require_admin
def update_git_source(source_ref):
    """Update a git source (any subset of the create fields).

    An update that changes which repository the source reads (provider,
    repository, branch, CodeCommit region or GitHub api_url), or which of
    its files it reads and as what (role or effective path_mappings), clears
    last_synced_commit; the next sync compares the branch head's tree with
    the stored files. The change is audited.
    ---
    tags:
      - Git sources
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: >
          Updated source (last_synced_commit is null after a change of provider, repository,
          branch, region, api_url, role or effective path_mappings)
      400:
        description: Validation error
      404:
        description: Not found
    """
    source, error = _source_or_404(source_ref)
    if error:
        return error
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object body required"}), 400
    try:
        update_source(source, data, member_id=_member_id())
    except GitSourceConfigError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(serialize_source(source))


@git_sources_api_bp.route("/git-sources/<source_ref>/sync", methods=["POST"])
@require_api_key
@require_admin
def sync_git_source(source_ref):
    """Queue a sync ("Sync now").
    ---
    tags:
      - Git sources
    security:
      - ApiKeyAuth: []
    requestBody:
      required: false
      content:
        application/json:
          schema:
            type: object
            properties:
              full:
                type: boolean
                description: >
                  Re-import every mapped file at head (still diff-only per record); also
                  resyncs a source whose last synced commit is no longer in the repository
    responses:
      202:
        description: Sync queued; poll poll_url until status is not queued/running
      400:
        description: The source is disabled
      404:
        description: Not found
      409:
        description: >
          A sync of this source is already queued or running (body is that run, or
          {"error"} when that run could not be read back)
    """
    source, error = _source_or_404(source_ref)
    if error:
        return error
    if not source.enabled:
        return jsonify({"error": f"Git source {source.name!r} is disabled; enable it to sync"}), 400
    data = request.get_json(silent=True) or {}
    try:
        run, created = enqueue_git_sync(source, "api", _member_id(), full=bool(data.get("full")))
    except ActiveRunConflict as exc:
        return jsonify({"error": str(exc)}), 409
    body = serialize_run(run)
    body["poll_url"] = f"/api/git-sources/{source.id}/runs/{run.id}"
    return jsonify(body), (202 if created else 409)


@git_sources_api_bp.route("/git-sources/<source_ref>/runs", methods=["GET"])
@require_api_key
@require_admin
def list_git_source_runs(source_ref):
    """Latest 100 sync runs of a source.
    ---
    tags:
      - Git sources
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: Sync runs, newest first
    """
    source, error = _source_or_404(source_ref)
    if error:
        return error
    runs = (GitSyncRun.query.filter_by(source_id=source.id)
            .order_by(GitSyncRun.queued_at.desc()).limit(100).all())
    return jsonify([serialize_run(r) for r in runs])


@git_sources_api_bp.route("/git-sources/<source_ref>/runs/<run_id>", methods=["GET"])
@require_api_key
@require_admin
def get_git_source_run(source_ref, run_id):
    """One sync run (commit range, counts, flagged files).
    ---
    tags:
      - Git sources
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: The run
      404:
        description: Not found
    """
    source, error = _source_or_404(source_ref)
    if error:
        return error
    run = db.session.get(GitSyncRun, run_id)
    if run is None or run.source_id != source.id:
        return jsonify({"error": "Run not found"}), 404
    return jsonify(serialize_run(run))


@git_sources_api_bp.route("/git-sources/<source_ref>/last-synced-commit", methods=["POST"])
@require_api_key
@require_admin
def set_git_source_commit(source_ref):
    """Set the last synced commit (cutover): the next sync diffs from it.

    A sync already running when it is set finishes without moving it.
    ---
    tags:
      - Git sources
    security:
      - ApiKeyAuth: []
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [commit_id]
            properties:
              commit_id: {type: string}
    responses:
      200:
        description: Updated source
      400:
        description: Invalid commit id
      404:
        description: Not found
    """
    source, error = _source_or_404(source_ref)
    if error:
        return error
    data = request.get_json(silent=True) or {}
    try:
        set_last_synced_commit(source, str(data.get("commit_id", "")), member_id=_member_id())
    except GitSourceConfigError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(serialize_source(source))
