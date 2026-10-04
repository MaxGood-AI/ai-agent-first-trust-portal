"""Admin pages for git sources, governance documents and change history.

All pages are admin-only. Public policy pages stay in ``app.routes.portal``.
"""

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from app.auth import require_admin, require_api_key
from app.models import db
from app.models.git_source import GitFileVersion, GitSource, GitSourceFile, GitSyncRun
from app.security import render_markdown
from app.services import governance_docs
from app.services.git_sources.service import (
    GitSourceConfigError,
    create_source,
    find_source,
    serialize_source,
    set_last_synced_commit,
    update_source,
)
from app.services.scheduler import ActiveRunConflict, enqueue_git_sync

admin_git_bp = Blueprint("admin_git", __name__)

FORM_FIELDS = ("name", "role", "provider", "repository", "branch", "region", "credential_mode",
               "schedule_cron")


def _member_id():
    member = getattr(g, "current_team_member", None)
    return member.id if member else None


def _form_payload(creating: bool) -> dict:
    data = {}
    for field in FORM_FIELDS:
        if field in request.form:
            value = request.form.get(field, "").strip()
            if value or field in ("region", "schedule_cron"):
                data[field] = value or None
    if not creating:
        data.pop("name", None)
        data.pop("role", None)
        data.pop("provider", None)
    data["enabled"] = request.form.get("enabled") == "on"
    role_arn = request.form.get("role_arn", "").strip()
    token = request.form.get("token", "").strip()
    if role_arn:
        data["credentials"] = {"role_arn": role_arn}
        external_id = request.form.get("external_id", "").strip()
        if external_id:
            data["credentials"]["external_id"] = external_id
    elif token:
        data["credentials"] = {"token": token}
    options = {"record_commits": request.form.get("record_commits") == "on"}
    history = request.form.get("history_limit", "").strip()
    if history:
        options["history_limit"] = history
    data["options"] = options
    return data


@admin_git_bp.route("/git-sources", methods=["GET"])
@require_api_key
@require_admin
def git_sources():
    sources = GitSource.query.order_by(GitSource.name).all()
    return render_template("admin/git_sources.html",
                           sources=[serialize_source(s) for s in sources])


@admin_git_bp.route("/git-sources", methods=["POST"])
@require_api_key
@require_admin
def git_source_create():
    try:
        source = create_source(_form_payload(creating=True), member_id=_member_id())
    except GitSourceConfigError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("admin_git.git_sources"))
    flash(f"Created git source {source.name}.", "success")
    return redirect(url_for("admin_git.git_source_detail", source_ref=source.id))


@admin_git_bp.route("/git-sources/<source_ref>", methods=["GET"])
@require_api_key
@require_admin
def git_source_detail(source_ref):
    source = find_source(source_ref)
    if source is None:
        abort(404)
    runs = (GitSyncRun.query.filter_by(source_id=source.id)
            .order_by(GitSyncRun.queued_at.desc()).limit(50).all())
    flagged = (GitSourceFile.query.filter_by(source_id=source.id)
               .filter(GitSourceFile.status.in_(("too_large", "error")))
               .order_by(GitSourceFile.path).limit(200).all())
    return render_template("admin/git_source_detail.html", source=serialize_source(source),
                           runs=runs, flagged=flagged)


@admin_git_bp.route("/git-sources/<source_ref>", methods=["POST"])
@require_api_key
@require_admin
def git_source_update(source_ref):
    source = find_source(source_ref)
    if source is None:
        abort(404)
    synced_commit = source.last_synced_commit
    try:
        update_source(source, _form_payload(creating=False), member_id=_member_id())
        if synced_commit and source.last_synced_commit is None:
            flash("Saved. The source now reads a different repository or branch, so its last synced "
                  "commit was cleared; the next sync compares the whole branch.", "success")
        else:
            flash("Saved.", "success")
    except GitSourceConfigError as exc:
        flash(str(exc), "error")
    return redirect(url_for("admin_git.git_source_detail", source_ref=source.id))


@admin_git_bp.route("/git-sources/<source_ref>/sync", methods=["POST"])
@require_api_key
@require_admin
def git_source_sync(source_ref):
    source = find_source(source_ref)
    if source is None:
        abort(404)
    if not source.enabled:
        flash(f"{source.name} is disabled; enable it to sync.", "error")
        return redirect(url_for("admin_git.git_source_detail", source_ref=source.id))
    try:
        run, created = enqueue_git_sync(source, "manual", _member_id(),
                                        full=request.form.get("full") == "on")
    except ActiveRunConflict:
        flash("A sync of this source is already queued or running; refresh to follow it.", "error")
        return redirect(url_for("admin_git.git_source_detail", source_ref=source.id))
    if created:
        flash(f"Sync queued (run {run.id[:8]}). Refresh to follow its progress.", "success")
    else:
        flash(f"A sync is already {run.status} (run {run.id[:8]}).", "error")
    return redirect(url_for("admin_git.git_source_detail", source_ref=source.id))


@admin_git_bp.route("/git-sources/<source_ref>/last-synced-commit", methods=["POST"])
@require_api_key
@require_admin
def git_source_set_commit(source_ref):
    source = find_source(source_ref)
    if source is None:
        abort(404)
    try:
        set_last_synced_commit(source, request.form.get("commit_id", ""), member_id=_member_id())
        flash(f"Last synced commit set to {source.last_synced_commit}.", "success")
    except GitSourceConfigError as exc:
        flash(str(exc), "error")
    return redirect(url_for("admin_git.git_source_detail", source_ref=source.id))


@admin_git_bp.route("/governance")
@require_api_key
@require_admin
def governance():
    return render_template("admin/governance.html", files=governance_docs.governance_files())


@admin_git_bp.route("/governance/files/<file_id>")
@require_api_key
@require_admin
def governance_file(file_id):
    record = db.session.get(GitSourceFile, file_id)
    if record is None:
        abort(404)
    source = db.session.get(GitSource, record.source_id)
    if source is None or source.role != "governance":
        abort(404)
    versions = governance_docs.file_versions(record.id)
    version_id = request.args.get("version") or record.current_version_id
    version = db.session.get(GitFileVersion, version_id) if version_id else None
    if version is not None and version.file_id != record.id:
        abort(404)
    rendered = None
    if version is not None and record.path.lower().endswith(".md"):
        _, body = governance_docs.split_front_matter(version.content)
        rendered = render_markdown(body)
    return render_template("admin/governance_file.html", record=record, source=source,
                           versions=versions, version=version, rendered=rendered)


@admin_git_bp.route("/governance/changes")
@require_api_key
@require_admin
def governance_changes():
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    source_id = request.args.get("source") or None
    pagination = governance_docs.change_history(source_id=source_id, page=page)
    sources = {s.id: s for s in GitSource.query.all()}
    return render_template("admin/governance_changes.html", pagination=pagination, sources=sources,
                           current_source=source_id or "")
