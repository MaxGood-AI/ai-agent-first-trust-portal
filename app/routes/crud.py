"""CRUD API routes for all entity types."""

import uuid

from flask import Blueprint, jsonify, request
from sqlalchemy import inspect as sa_inspect

from app.auth import require_api_key
from app.models import (
    db, Control, System, Vendor, Policy, TestRecord,
    Evidence, RiskRegister, PentestFinding,
)

crud_bp = Blueprint("crud", __name__)


def _serialize(instance):
    """Generic serializer: converts a model instance to a dict."""
    mapper = sa_inspect(type(instance))
    result = {}
    for attr in mapper.column_attrs:
        value = getattr(instance, attr.key)
        if hasattr(value, "isoformat"):
            value = value.isoformat()
        result[attr.key] = value
    return result


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
        items = model_class.query.all()
        return jsonify([_serialize(item) for item in items])

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
        item = db.session.get(model_class, item_id)
        if not item:
            return jsonify({"error": "Not found"}), 404
        return jsonify(_serialize(item))

    @crud_bp.route(f"/{plural_name}", methods=["POST"], endpoint=f"create_{plural_name}")
    @require_api_key
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
        if not data:
            return jsonify({"error": "Request body required"}), 400

        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400

        if "id" not in data:
            data["id"] = str(uuid.uuid4())

        mapper = sa_inspect(model_class)
        valid_columns = {attr.key for attr in mapper.column_attrs}
        filtered = {k: v for k, v in data.items() if k in valid_columns}

        instance = model_class(**filtered)
        db.session.add(instance)
        db.session.commit()
        return jsonify(_serialize(instance)), 201

    @crud_bp.route(f"/{plural_name}/<item_id>", methods=["PUT"], endpoint=f"update_{plural_name}")
    @require_api_key
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
        if not data:
            return jsonify({"error": "Request body required"}), 400

        mapper = sa_inspect(model_class)
        valid_columns = {attr.key for attr in mapper.column_attrs}
        for key, value in data.items():
            if key in valid_columns and key != "id":
                setattr(item, key, value)

        db.session.commit()
        return jsonify(_serialize(item))

    @crud_bp.route(f"/{plural_name}/<item_id>", methods=["DELETE"], endpoint=f"delete_{plural_name}")
    @require_api_key
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
