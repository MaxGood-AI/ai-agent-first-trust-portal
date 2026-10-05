"""Admin pages for the evidence store and its evidence documents.

All pages are admin-only (``/admin/evidence-store``). Evidence documents are
never shown on a public page.
"""

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from app.auth import require_admin, require_api_key
from app.models import Control, TestRecord, db
from app.models.evidence_store import DOCUMENT_KINDS, OBJECT_KINDS, OBJECT_STATUSES, EvidenceDocument
from app.services.evidence_store import NOT_CONFIGURED, StoreNotConfigured, keys, service
from app.services.scheduler import ActiveRunConflict

admin_store_bp = Blueprint("admin_store", __name__)

OBJECTS_PER_PAGE = 100
DOCUMENTS_SHOWN = 200


def _member_id():
    member = getattr(g, "current_team_member", None)
    return member.id if member else None


def _document_or_404(document_id):
    document = db.session.get(EvidenceDocument, document_id)
    if document is None:
        abort(404)
    return document


@admin_store_bp.route("/evidence-store", methods=["GET"])
@require_api_key
@require_admin
def evidence_store():
    kind = request.args.get("kind") or ""
    status_filter = request.args.get("status") or ""
    if kind not in OBJECT_KINDS:
        kind = ""
    if status_filter not in OBJECT_STATUSES:
        status_filter = ""
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    objects = service.objects_query(kind or None, status_filter or None).paginate(
        page=page, per_page=OBJECTS_PER_PAGE, error_out=False)
    runs = service.latest_runs(20)
    last_finished = next((run for run in runs if run.status not in ("queued", "running")), None)
    documents = (EvidenceDocument.query.order_by(EvidenceDocument.created_at.desc())
                 .limit(DOCUMENTS_SHOWN).all())
    return render_template("admin/evidence_store.html", status=service.status(), runs=runs, objects=objects,
                           anomalies=((last_finished.details or {}).get("anomalies") or []) if last_finished else [],
                           documents=documents, kinds=OBJECT_KINDS, statuses=OBJECT_STATUSES,
                           current_kind=kind, current_status=status_filter, not_configured=NOT_CONFIGURED)


@admin_store_bp.route("/evidence-store/sync", methods=["POST"])
@require_api_key
@require_admin
def evidence_store_sync():
    try:
        run, created = service.enqueue_sync("manual", _member_id())
    except StoreNotConfigured:
        flash(NOT_CONFIGURED, "error")
        return redirect(url_for("admin_store.evidence_store"))
    except ActiveRunConflict:
        flash("A sync is already queued or running; refresh to follow it.", "error")
        return redirect(url_for("admin_store.evidence_store"))
    if created:
        flash(f"Sync queued (run {run.id[:8]}). Refresh to follow its progress.", "success")
    else:
        flash(f"A sync is already {run.status} (run {run.id[:8]}).", "error")
    return redirect(url_for("admin_store.evidence_store"))


@admin_store_bp.route("/evidence-store/documents/<document_id>", methods=["GET"])
@require_api_key
@require_admin
def evidence_document(document_id):
    document = _document_or_404(document_id)
    controls = Control.query.order_by(Control.control_id_short, Control.name).all()
    tests = TestRecord.query.order_by(TestRecord.name).all()
    return render_template("admin/evidence_document.html",
                           document=service.serialize_document(document, with_links=True),
                           controls=controls, tests=tests, kinds=DOCUMENT_KINDS,
                           previewable=keys.is_text(document.key) and document.size <= service.PREVIEW_LIMIT)


@admin_store_bp.route("/evidence-store/documents/<document_id>/view", methods=["GET"])
@require_api_key
@require_admin
def evidence_document_view(document_id):
    document = _document_or_404(document_id)
    if not keys.is_text(document.key):
        abort(404)
    try:
        content = service.document_bytes(document, limit=service.PREVIEW_LIMIT)
    except service.DocumentUnavailable as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin_store.evidence_document", document_id=document.id))
    return render_template("admin/evidence_document_view.html", document=service.serialize_document(document),
                           text=content.decode("utf-8", "replace"))


@admin_store_bp.route("/evidence-store/documents/<document_id>/links", methods=["POST"])
@require_api_key
@require_admin
def evidence_document_link(document_id):
    document = _document_or_404(document_id)
    target = request.form.get("target", "")
    kind, _, target_id = target.partition(":")
    try:
        service.add_link(document, control_id=target_id if kind == "control" else None,
                         test_id=target_id if kind == "test" else None, member_id=_member_id())
        db.session.commit()
        flash("Linked.", "success")
    except service.EvidenceStoreError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("admin_store.evidence_document", document_id=document.id))


@admin_store_bp.route("/evidence-store/documents/<document_id>/links/<link_id>/delete", methods=["POST"])
@require_api_key
@require_admin
def evidence_document_unlink(document_id, link_id):
    document = _document_or_404(document_id)
    if service.remove_link(document, link_id):
        db.session.commit()
        flash("Link removed.", "success")
    else:
        flash("No such link.", "error")
    return redirect(url_for("admin_store.evidence_document", document_id=document.id))
