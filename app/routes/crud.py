"""CRUD API routes for all entity types.

Client members reach only the list/get routes ``app.auth`` allows them
(systems, vendors, policies); for policies they see approved ones only - a
draft is left out of the list and answers 404. URL columns
(``app.security.URL_FIELDS``) accept only http(s) URLs on create and update.

Values are checked against their columns before anything is written
(:func:`column_errors`): text columns take strings no longer than the column,
integer and boolean columns take numbers and booleans, date-time columns take
ISO 8601 strings; a violation answers 400. A write that breaks a database
constraint answers 409 for an id that already exists and 400 otherwise (an
unknown reference such as a missing ``control_id``, or a missing required
value).
"""

import base64
import uuid
from datetime import date, datetime

from flask import Blueprint, jsonify, request
from sqlalchemy import Boolean, Date, DateTime, Float, Integer, LargeBinary, Numeric, String
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import DataError, IntegrityError

from app.auth import current_member_is_client, require_api_key, require_writer
from app.models import (
    db, Control, System, Vendor, Policy, TestRecord,
    Evidence, RiskRegister, PentestFinding,
)
from app.security import url_fields_error

crud_bp = Blueprint("crud", __name__)

# Rows a client member may see, by model: a SQLAlchemy filter expression.
CLIENT_VISIBLE = {
    Policy: lambda: Policy.status == "approved",
}


def _client_filter(model_class):
    """The visibility filter for the current member, or None for no filter."""
    if model_class in CLIENT_VISIBLE and current_member_is_client():
        return CLIENT_VISIBLE[model_class]()
    return None


def _serialize(instance):
    """Generic serializer: converts a model instance to a dict."""
    mapper = sa_inspect(type(instance))
    result = {}
    for attr in mapper.column_attrs:
        col = attr.columns[0]
        if isinstance(col.type, LargeBinary):
            result["has_file"] = getattr(instance, attr.key) is not None
            continue
        value = getattr(instance, attr.key)
        if hasattr(value, "isoformat"):
            value = value.isoformat()
        result[attr.key] = value
    return result


def decode_file_data(data):
    """Decode base64 file_data in a request dict to bytes. Modifies in place."""
    if "file_data" in data and isinstance(data["file_data"], str):
        try:
            data["file_data"] = base64.b64decode(data["file_data"])
        except Exception:
            return "Invalid base64 in file_data"
    return None


def _parse_datetime(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


def _column_error(key, column, value):
    """Why ``value`` does not fit ``column`` (a message), or None. Date-time
    strings are returned parsed as the second element."""
    column_type = column.type
    if value is None:
        return None, value
    if isinstance(column_type, String):
        if not isinstance(value, str):
            return f"{key} must be a string", value
        if column_type.length and len(value) > column_type.length:
            return f"{key} is longer than {column_type.length} characters", value
    elif isinstance(column_type, Boolean):
        if not isinstance(value, bool):
            return f"{key} must be true or false", value
    elif isinstance(column_type, Integer):
        if isinstance(value, bool) or not isinstance(value, int):
            return f"{key} must be an integer", value
    elif isinstance(column_type, (Float, Numeric)):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return f"{key} must be a number", value
    elif isinstance(column_type, (DateTime, Date)):
        parsed = _parse_datetime(value)
        if parsed is None:
            return f"{key} must be an ISO 8601 date or date-time", value
        return None, parsed.date() if isinstance(column_type, Date) and not isinstance(column_type, DateTime) \
            else parsed
    elif isinstance(column_type, LargeBinary):
        if not isinstance(value, (bytes, bytearray)):
            return f"{key} must be base64-encoded data", value
    return None, value


def column_errors(model_class, data):
    """Check (and normalise, in place) the values of ``data`` against the
    columns of ``model_class``; returns the first problem, or None.

    Keys that are not columns are ignored. ISO 8601 strings for date-time
    columns are replaced by ``datetime`` values.
    """
    columns = {attr.key: attr.columns[0] for attr in sa_inspect(model_class).column_attrs}
    for key in list(data):
        column = columns.get(key)
        if column is None:
            continue
        error, value = _column_error(key, column, data[key])
        if error:
            return error
        data[key] = value
    return None


def _commit_or_error():
    """Commit; on a constraint violation roll back and return an error response."""
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        orig = getattr(exc, "orig", None)
        if getattr(orig, "pgcode", None) == "23505" or "UNIQUE constraint failed" in str(orig):
            return jsonify({"error": "A record with this id or unique value already exists"}), 409
        return jsonify({"error": "The values break a database constraint: a referenced record "
                                 "does not exist or a required value is missing"}), 400
    except DataError:
        db.session.rollback()
        return jsonify({"error": "A value does not fit its column"}), 400
    return None


def _register_crud(model_class, plural_name, required_fields=None):
    """Register list, get, create, update, delete routes for a model."""
    required_fields = required_fields or ["name"]

    @crud_bp.route(f"/{plural_name}", endpoint=f"list_{plural_name}")
    @require_api_key
    def list_all():
        f"""List all {plural_name}.
        ---
        tags:
          - {plural_name.replace('-', ' ').title()}
        security:
          - ApiKeyAuth: []
        responses:
          200:
            description: List of {plural_name}
        """
        query = model_class.query
        visible = _client_filter(model_class)
        if visible is not None:
            query = query.filter(visible)
        return jsonify([_serialize(item) for item in query.all()])

    @crud_bp.route(f"/{plural_name}/<item_id>", endpoint=f"get_{plural_name}")
    @require_api_key
    def get_one(item_id):
        f"""Get a single {plural_name[:-1]} by ID.
        ---
        tags:
          - {plural_name.replace('-', ' ').title()}
        security:
          - ApiKeyAuth: []
        parameters:
          - name: item_id
            in: path
            required: true
            schema:
              type: string
        responses:
          200:
            description: The {plural_name[:-1]}
          404:
            description: Not found
        """
        query = model_class.query.filter(sa_inspect(model_class).primary_key[0] == item_id)
        visible = _client_filter(model_class)
        if visible is not None:
            query = query.filter(visible)
        item = query.first()
        if not item:
            return jsonify({"error": "Not found"}), 404
        return jsonify(_serialize(item))

    @crud_bp.route(f"/{plural_name}", methods=["POST"], endpoint=f"create_{plural_name}")
    @require_api_key
    @require_writer
    def create():
        f"""Create a new {plural_name[:-1]}.
        ---
        tags:
          - {plural_name.replace('-', ' ').title()}
        security:
          - ApiKeyAuth: []
        responses:
          201:
            description: Created
          400:
            description: Validation error
        """
        data = request.get_json()
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Request body required"}), 400

        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400

        if "id" not in data:
            data["id"] = str(uuid.uuid4())

        err = (decode_file_data(data) or url_fields_error(model_class.__tablename__, data)
               or column_errors(model_class, data))
        if err:
            return jsonify({"error": err}), 400

        mapper = sa_inspect(model_class)
        valid_columns = {attr.key for attr in mapper.column_attrs}
        filtered = {k: v for k, v in data.items() if k in valid_columns}

        instance = model_class(**filtered)
        db.session.add(instance)
        failure = _commit_or_error()
        if failure:
            return failure
        return jsonify(_serialize(instance)), 201

    @crud_bp.route(f"/{plural_name}/<item_id>", methods=["PUT"], endpoint=f"update_{plural_name}")
    @require_api_key
    @require_writer
    def update(item_id):
        f"""Update an existing {plural_name[:-1]}.
        ---
        tags:
          - {plural_name.replace('-', ' ').title()}
        security:
          - ApiKeyAuth: []
        parameters:
          - name: item_id
            in: path
            required: true
            schema:
              type: string
        responses:
          200:
            description: Updated
          404:
            description: Not found
        """
        item = db.session.get(model_class, item_id)
        if not item:
            return jsonify({"error": "Not found"}), 404

        data = request.get_json()
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Request body required"}), 400
        err = (decode_file_data(data) or url_fields_error(model_class.__tablename__, data)
               or column_errors(model_class, data))
        if err:
            return jsonify({"error": err}), 400

        mapper = sa_inspect(model_class)
        valid_columns = {attr.key for attr in mapper.column_attrs}
        for key, value in data.items():
            if key in valid_columns and key != "id":
                setattr(item, key, value)

        failure = _commit_or_error()
        if failure:
            return failure
        return jsonify(_serialize(item))

    @crud_bp.route(f"/{plural_name}/<item_id>", methods=["DELETE"], endpoint=f"delete_{plural_name}")
    @require_api_key
    @require_writer
    def delete(item_id):
        f"""Delete a {plural_name[:-1]}.
        ---
        tags:
          - {plural_name.replace('-', ' ').title()}
        security:
          - ApiKeyAuth: []
        parameters:
          - name: item_id
            in: path
            required: true
            schema:
              type: string
        responses:
          200:
            description: Deleted
          404:
            description: Not found
        """
        item = db.session.get(model_class, item_id)
        if not item:
            return jsonify({"error": "Not found"}), 404

        db.session.delete(item)
        db.session.commit()
        return jsonify({"deleted": item_id})


# Register CRUD for all entity types
_register_crud(Control, "controls", required_fields=["name", "category"])
_register_crud(System, "systems", required_fields=["name"])
_register_crud(Vendor, "vendors", required_fields=["name"])
_register_crud(Policy, "policies", required_fields=["title", "category"])
_register_crud(TestRecord, "tests", required_fields=["name", "control_id"])
_register_crud(Evidence, "evidence", required_fields=["test_record_id", "evidence_type"])
_register_crud(RiskRegister, "risks", required_fields=["name"])
_register_crud(PentestFinding, "pentest-findings", required_fields=["layer"])
