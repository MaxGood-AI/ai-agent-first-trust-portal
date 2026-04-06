"""Export compliance data from DB to JSON files (inverse of init)."""

import json
import logging
import os
import subprocess
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Reverse field maps: model column → JSON key
# These are the inverse of each loader's field_map
REVERSE_FIELD_MAPS = {
    "controls": {"category": "tsc_category", "source_category": "category"},
    "systems": {"system_type": "type"},
}

# Reverse value maps: model value → JSON value
REVERSE_VALUE_MAPS = {
    "tests": {
        "status": {"passed": "success", "failed": "failure", "pending": "not_run", "not_applicable": "excluded"},
        "evidence_status": {"submitted": "up_to_date", "due_soon": "due"},
    },
}


def export_all(output_dir, include_audit_log=False):
    """Export all compliance tables to JSON files."""
    from app.models import (
        Control, TestRecord, Policy, System, Vendor,
        Evidence, RiskRegister, db,
    )

    os.makedirs(output_dir, exist_ok=True)

    exports = [
        ("controls.json", Control, "controls"),
        ("systems.json", System, "systems"),
        ("tests.json", TestRecord, "tests"),
        ("policy-index.json", Policy, "policies"),
        ("vendors.json", Vendor, "vendors"),
        ("evidence/evidence-index.json", Evidence, "evidence"),
        ("risk-register.json", RiskRegister, "risk_register"),
    ]

    for filename, model, config_key in exports:
        records = model.query.all()
        data = [_serialize_record(r, config_key) for r in records]
        data.sort(key=lambda x: x.get("id", ""))

        filepath = os.path.join(output_dir, filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str, sort_keys=True)

        logger.info("Exported %d records to %s", len(data), filename)

    if include_audit_log:
        _export_audit_log(output_dir)

    return {"status": "success", "output_dir": output_dir}


def _serialize_record(record, config_key):
    """Serialize a model instance to a dict, applying reverse field/value maps."""
    from sqlalchemy import inspect as sa_inspect
    mapper = sa_inspect(type(record))
    data = {}
    reverse_fields = REVERSE_FIELD_MAPS.get(config_key, {})
    reverse_values = REVERSE_VALUE_MAPS.get(config_key, {})

    for attr in mapper.column_attrs:
        col_name = attr.key
        value = getattr(record, col_name)

        if col_name in ("other_data", "created_at", "updated_at"):
            continue

        if col_name in reverse_values and value in reverse_values[col_name]:
            value = reverse_values[col_name][value]

        json_key = reverse_fields.get(col_name, col_name)

        if isinstance(value, datetime):
            value = value.isoformat()

        data[json_key] = value

    other_data = getattr(record, "other_data", None)
    if other_data and isinstance(other_data, dict):
        for k, v in other_data.items():
            if not k.startswith("_original_") and k not in data:
                data[k] = v

    return data


def _export_audit_log(output_dir):
    """Export the audit log as a separate JSON file."""
    from app.models.audit_log import AuditLog
    records = AuditLog.query.order_by(AuditLog.changed_at).all()
    data = [{
        "id": r.id,
        "table_name": r.table_name,
        "record_id": r.record_id,
        "action": r.action,
        "old_values": r.old_values,
        "new_values": r.new_values,
        "changed_by": r.changed_by,
        "changed_at": r.changed_at.isoformat() if r.changed_at else None,
    } for r in records]
    filepath = os.path.join(output_dir, "audit-log.json")
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)
    logger.info("Exported %d audit log entries to audit-log.json", len(data))


def git_commit_and_push(output_dir, push=False):
    """Commit exported changes and optionally push."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    subprocess.run(["git", "add", "."], cwd=output_dir, check=True)

    result = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=output_dir,
        capture_output=True,
    )
    if result.returncode == 0:
        logger.info("No changes to commit")
        return False

    subprocess.run(
        ["git", "commit", "-m", f"Compliance data export {timestamp}"],
        cwd=output_dir,
        check=True,
    )
    logger.info("Committed export at %s", timestamp)

    if push:
        subprocess.run(["git", "push"], cwd=output_dir, check=True)
        logger.info("Pushed to remote")

    return True
