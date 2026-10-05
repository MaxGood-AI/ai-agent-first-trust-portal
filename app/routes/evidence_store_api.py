"""API routes for the evidence store and its evidence documents.

- ``/api/evidence-store``, ``.../sync``, ``.../runs/<id>`` and ``.../verify``
  are for compliance admins; ``.../objects`` for team members.
- ``/api/evidence-documents`` and ``/<id>`` (and the document's bytes,
  ``/<id>/content``) are for team members (``human`` and ``agent``);
  linking a document to a control or a test is for compliance admins.

None of them is open to ``client`` keys or to anonymous requests, and no
public page shows a document. Syncs are asynchronous: ``POST .../sync``
queues a run and returns its id and ``poll_url``.
"""

from flask import Blueprint, Response, g, jsonify, request
from werkzeug.wsgi import wrap_file

from app.auth import require_admin, require_api_key, require_team
from app.models import db
from app.models.evidence_store import DOCUMENT_KINDS, OBJECT_KINDS, OBJECT_STATUSES, EvidenceDocument, \
    EvidenceStoreSyncRun
from app.services.evidence_store import NOT_CONFIGURED, StoreNotConfigured, store_bucket
from app.services.evidence_store import service
from app.services.scheduler import ActiveRunConflict

evidence_store_api_bp = Blueprint("evidence_store_api", __name__)

DEFAULT_PER_PAGE = 100
MAX_PER_PAGE = 500
DEFAULT_VERIFY_ITEMS = 500
MAX_VERIFY_ITEMS = 2000
MAX_FULL_VERIFY_ITEMS = 20
# Bytes of version bodies one verification slice reads at most (a slice always checks at least one record).
VERIFY_SLICE_BYTES = 256 * 1024 * 1024


def _member_id():
    member = getattr(g, "current_team_member", None)
    return member.id if member else None


def _paging():
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = max(1, min(int(request.args.get("per_page", DEFAULT_PER_PAGE)), MAX_PER_PAGE))
    except ValueError:
        return None
    return page, per_page


def _paginated(query, serialize):
    paging = _paging()
    if paging is None:
        return jsonify({"error": "page and per_page must be integers"}), 400
    page, per_page = paging
    total = query.order_by(None).count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return jsonify({"items": [serialize(item) for item in items], "page": page, "per_page": per_page,
                    "total": total, "pages": (total + per_page - 1) // per_page})


def _document_or_404(document_id):
    document = db.session.get(EvidenceDocument, document_id)
    if document is None:
        return None, (jsonify({"error": "Evidence document not found"}), 404)
    return document, None


@evidence_store_api_bp.route("/evidence-store", methods=["GET"])
@require_api_key
@require_admin
def evidence_store_status():
    """Evidence store status: bucket, recorded objects and the latest sync.
    ---
    tags:
      - Evidence store
    security:
      - ApiKeyAuth: []
    responses:
      200:
        description: >
          {"configured", "bucket", "objects", "objects_by_status", "objects_by_kind", "documents",
          "last_run"}; configured is false while EVIDENCE_STORE_BUCKET is unset
      403:
        description: Not a compliance admin
    """
    return jsonify(service.status())


@evidence_store_api_bp.route("/evidence-store/sync", methods=["POST"])
@require_api_key
@require_admin
def evidence_store_sync():
    """Queue a sync of the evidence store ("Sync now").
    ---
    tags:
      - Evidence store
    security:
      - ApiKeyAuth: []
    responses:
      202:
        description: Sync queued; poll poll_url until status is not queued/running
      400:
        description: The evidence store is not configured (EVIDENCE_STORE_BUCKET is not set)
      409:
        description: A sync is already queued or running (body is that run, or {"error"})
    """
    try:
        run, created = service.enqueue_sync("api", _member_id())
    except StoreNotConfigured:
        return jsonify({"error": NOT_CONFIGURED}), 400
    except ActiveRunConflict as exc:
        return jsonify({"error": str(exc)}), 409
    body = service.serialize_run(run)
    body["poll_url"] = f"/api/evidence-store/runs/{run.id}"
    return jsonify(body), (202 if created else 409)


@evidence_store_api_bp.route("/evidence-store/runs/<run_id>", methods=["GET"])
@require_api_key
@require_admin
def evidence_store_run(run_id):
    """One evidence store sync run: status, counts, anomalies and errors.
    ---
    tags:
      - Evidence store
    security:
      - ApiKeyAuth: []
    parameters:
      - name: run_id
        in: path
        required: true
        schema:
          type: string
    responses:
      200:
        description: >
          The run: status (queued | running | success | partial | failure | unchanged), counts
          (listed, new, ingested, unchanged, recorded, duplicate, rejected, non_conforming, too_large,
          errors, anomalies, reevaluated), details (by_kind, anomalies, errors, conflicts; errors name
          the error class and code only), error_message (the class and code of a failed run) and the
          bucket's default retention the run read (retention_mode, retention_days)
      404:
        description: Not found
    """
    run = db.session.get(EvidenceStoreSyncRun, run_id)
    if run is None:
        return jsonify({"error": "Run not found"}), 404
    return jsonify(service.serialize_run(run))


@evidence_store_api_bp.route("/evidence-store/objects", methods=["GET"])
@require_api_key
@require_team
def evidence_store_objects():
    """Object versions the portal recorded from the evidence store (team members).
    ---
    tags:
      - Evidence store
    security:
      - ApiKeyAuth: []
    parameters:
      - name: kind
        in: query
        schema:
          type: string
          enum: [decision_log, decision_log_sidecar, pentest_evidence, evidence_document, unmapped]
      - name: status
        in: query
        schema:
          type: string
          enum: [ingested, unchanged, recorded, duplicate, rejected, non_conforming, too_large, error,
                 acknowledged, erased]
      - name: page
        in: query
        schema:
          type: integer
          default: 1
      - name: per_page
        in: query
        schema:
          type: integer
          default: 100
          maximum: 500
    responses:
      200:
        description: >
          {"items", "page", "per_page", "total", "pages"}, newest first; each item has the key,
          version id, SHA-256, the stored composite checksum of a multipart upload
          (composite_checksum, null for a full-object checksum), size, ETag, Object Lock mode and
          retain-until date, kind, status,
          detail, the recording sync run, attempts, import_info and any erasure or acknowledgement
      400:
        description: Invalid filter or paging parameter
      403:
        description: Client keys are refused
    """
    kind = request.args.get("kind") or None
    status_filter = request.args.get("status") or None
    if kind is not None and kind not in OBJECT_KINDS:
        return jsonify({"error": f"kind must be one of {', '.join(OBJECT_KINDS)}"}), 400
    if status_filter is not None and status_filter not in OBJECT_STATUSES:
        return jsonify({"error": f"status must be one of {', '.join(OBJECT_STATUSES)}"}), 400
    return _paginated(service.objects_query(kind, status_filter), service.serialize_object)


@evidence_store_api_bp.route("/evidence-store/verify", methods=["GET"])
@require_api_key
@require_admin
def evidence_store_verify():
    """Verify the evidence store against the portal's records (compliance admins).

    One slice per request, within two budgets: at most max_items records (each checked with
    HeadObject; every outcome that is not a straightforward import - unchanged, duplicate,
    rejected, too_large - re-derived from its version's body) and at most 256 MiB of version
    bodies read (a slice always checks at least one record), then at most max_items listed
    versions; continue with next_cursor until it is null (budget_exhausted: this slice stopped
    at a budget). A verification through the API is the sum of its slices: it is valid when
    every slice is. With full (every body re-read), a slice holds at most 20 records or
    versions. The bucket is checked on every slice, the evidence documents and the store's
    pentest findings on the first. python -m cli audit-verify --evidence-store has no limits.
    ---
    tags:
      - Evidence store
    security:
      - ApiKeyAuth: []
    parameters:
      - name: cursor
        in: query
        schema:
          type: string
        description: next_cursor of the previous slice
      - name: max_items
        in: query
        schema:
          type: integer
          default: 500
          maximum: 2000
        description: Records, then listed versions, per slice (at most 20 with full)
      - name: full
        in: query
        schema:
          type: boolean
        description: Also re-read every body and recompute its SHA-256 (slices of at most 20)
    responses:
      200:
        description: >
          {"status": valid | unverified | broken (of this slice), "bucket_check" (versioning,
          default retention against retention_floor_days, bucket policy and lifecycle issues,
          erasure_principals, retention_floor_lowerings with its count), "documents" and
          "store_conflicts" with "store_conflicts_count" (first slice; conflicts are
          informational), "store_findings" (first slice: store-namespace findings no store
          object imported), "records" (failures - import outcomes included -, erased,
          acknowledged, pending, retention_expired, refusals, each with its count;
          rederived, bytes_read), "listing", "failure_count", "unrecorded_count", "bytes_read",
          "budget_exhausted", "max_items", "max_bytes", "next_cursor"}
      400:
        description: Not configured, or an invalid parameter
    """
    from app.services.evidence_store import store, verify

    bucket = store_bucket()
    if bucket is None:
        return jsonify({"error": NOT_CONFIGURED}), 400
    try:
        max_items = max(1, min(int(request.args.get("max_items", DEFAULT_VERIFY_ITEMS)), MAX_VERIFY_ITEMS))
        verify.decode_cursor(request.args.get("cursor"))
    except ValueError as exc:
        return jsonify({"error": str(exc) if "cursor" in str(exc) else "max_items must be an integer"}), 400
    full = request.args.get("full", "").lower() in ("1", "true", "yes")
    if full:
        max_items = min(max_items, MAX_FULL_VERIFY_ITEMS)
    db.session.commit()  # no transaction is held while S3 answers
    result = verify.verify_store(db.session, store.s3_client(), bucket, full=full,
                                 cursor=request.args.get("cursor"), max_items=max_items,
                                 max_bytes=VERIFY_SLICE_BYTES)
    result["max_items"] = max_items
    result["max_bytes"] = VERIFY_SLICE_BYTES
    return jsonify(result)


@evidence_store_api_bp.route("/evidence-documents", methods=["GET"])
@require_api_key
@require_team
def list_evidence_documents():
    """Evidence documents from the evidence store (team members only; never public).
    ---
    tags:
      - Evidence documents
    security:
      - ApiKeyAuth: []
    parameters:
      - name: kind
        in: query
        schema:
          type: string
          enum: [code-review, pentest-report, evidence-artifact]
      - name: control_id
        in: query
        schema:
          type: string
        description: Only documents linked to this control
      - name: test_id
        in: query
        schema:
          type: string
        description: Only documents linked to this test
      - name: page
        in: query
        schema:
          type: integer
          default: 1
      - name: per_page
        in: query
        schema:
          type: integer
          default: 100
          maximum: 500
    responses:
      200:
        description: '{"items", "page", "per_page", "total", "pages"}, newest first'
      400:
        description: Invalid filter or paging parameter
      403:
        description: Client keys are refused
    """
    from app.models.evidence_store import EvidenceDocumentLink

    kind = request.args.get("kind") or None
    if kind is not None and kind not in DOCUMENT_KINDS:
        return jsonify({"error": f"kind must be one of {', '.join(DOCUMENT_KINDS)}"}), 400
    query = EvidenceDocument.query
    if kind:
        query = query.filter(EvidenceDocument.kind == kind)
    control_id, test_id = request.args.get("control_id"), request.args.get("test_id")
    if control_id or test_id:
        links = db.session.query(EvidenceDocumentLink.document_id)
        if control_id:
            links = links.filter(EvidenceDocumentLink.control_id == control_id)
        if test_id:
            links = links.filter(EvidenceDocumentLink.test_record_id == test_id)
        query = query.filter(EvidenceDocument.id.in_(links))
    query = query.order_by(EvidenceDocument.created_at.desc(), EvidenceDocument.id)
    return _paginated(query, service.serialize_document)


@evidence_store_api_bp.route("/evidence-documents/<document_id>", methods=["GET"])
@require_api_key
@require_team
def get_evidence_document(document_id):
    """One evidence document: metadata, SHA-256, version id and links (team members).
    ---
    tags:
      - Evidence documents
    security:
      - ApiKeyAuth: []
    parameters:
      - name: document_id
        in: path
        required: true
        schema:
          type: string
    responses:
      200:
        description: The document with its links to controls and tests
      404:
        description: Not found
    """
    document, error = _document_or_404(document_id)
    if error:
        return error
    return jsonify(service.serialize_document(document, with_links=True))


@evidence_store_api_bp.route("/evidence-documents/<document_id>/content", methods=["GET"])
@require_api_key
@require_team
def get_evidence_document_content(document_id):
    """The document's bytes, read from its exact store version (team members).

    Served only when their SHA-256 equals the record, as an attachment. The bytes are spooled
    (in memory up to 1 MiB, then on disk) and checked before the response starts; at most two
    documents are read at once per server process.
    ---
    tags:
      - Evidence documents
    security:
      - ApiKeyAuth: []
    parameters:
      - name: document_id
        in: path
        required: true
        schema:
          type: string
    responses:
      200:
        description: The document (Content-Disposition attachment, X-Content-Type-Options nosniff)
        content:
          application/octet-stream:
            schema:
              type: string
              format: binary
      404:
        description: Not found
      410:
        description: The version was erased (documented erasure)
      413:
        description: Larger than the portal serves (32 MiB)
      429:
        description: Other documents are being read; retry after the Retry-After seconds
      502:
        description: The store cannot be read, or holds bytes whose SHA-256 differs from the record
      503:
        description: The evidence store is not configured
    """
    document, error = _document_or_404(document_id)
    if error:
        return error
    try:
        spool = service.open_document(document)
    except service.DocumentUnavailable as exc:
        headers = {"Retry-After": str(service.RETRY_AFTER_SECONDS)} if exc.status == 429 else {}
        return jsonify({"error": str(exc)}), exc.status, headers
    size = spool.seek(0, 2)
    spool.seek(0)
    return Response(wrap_file(request.environ, spool), mimetype=service.serve_type(document), direct_passthrough=True,
                    headers={
                        "Content-Length": str(size),
                        "Content-Disposition": f'attachment; filename="{service.download_name(document)}"',
                        "X-Content-Type-Options": "nosniff",
                        "Cache-Control": "no-store",
                    })


@evidence_store_api_bp.route("/evidence-documents/<document_id>/links", methods=["POST"])
@require_api_key
@require_admin
def add_evidence_document_link(document_id):
    """Link a document to a control or a test (compliance admins; audited).
    ---
    tags:
      - Evidence documents
    security:
      - ApiKeyAuth: []
    parameters:
      - name: document_id
        in: path
        required: true
        schema:
          type: string
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            description: Exactly one of control_id and test_id
            properties:
              control_id: {type: string}
              test_id: {type: string}
    responses:
      201:
        description: The link
      400:
        description: Neither or both targets, an unknown target, or an existing link
      404:
        description: Document not found
    """
    document, error = _document_or_404(document_id)
    if error:
        return error
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object body required"}), 400
    control_id, test_id = data.get("control_id"), data.get("test_id")
    if any(value is not None and not isinstance(value, str) for value in (control_id, test_id)):
        return jsonify({"error": "control_id and test_id must be strings"}), 400
    try:
        link = service.add_link(document, control_id=control_id, test_id=test_id, member_id=_member_id())
        db.session.commit()
    except service.EvidenceStoreError as exc:
        db.session.rollback()
        return jsonify({"error": str(exc)}), 400
    return jsonify(service.serialize_link(link)), 201


@evidence_store_api_bp.route("/evidence-documents/<document_id>/links/<link_id>", methods=["DELETE"])
@require_api_key
@require_admin
def remove_evidence_document_link(document_id, link_id):
    """Remove a document's link (compliance admins; audited).
    ---
    tags:
      - Evidence documents
    security:
      - ApiKeyAuth: []
    parameters:
      - name: document_id
        in: path
        required: true
        schema:
          type: string
      - name: link_id
        in: path
        required: true
        schema:
          type: string
    responses:
      200:
        description: '{"deleted": link_id}'
      404:
        description: Document or link not found
    """
    document, error = _document_or_404(document_id)
    if error:
        return error
    if not service.remove_link(document, link_id):
        return jsonify({"error": "Link not found"}), 404
    db.session.commit()
    return jsonify({"deleted": link_id})
