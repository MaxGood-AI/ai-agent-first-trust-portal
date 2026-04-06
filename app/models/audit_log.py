"""Audit log model — records all compliance data changes."""

from app.models import db


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    table_name = db.Column(db.String(100), nullable=False)
    record_id = db.Column(db.String(36), nullable=False)
    action = db.Column(db.String(10), nullable=False)
    old_values = db.Column(db.JSON)
    new_values = db.Column(db.JSON)
    changed_by = db.Column(db.String(36))
    changed_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=db.func.now()
    )
    row_hash = db.Column(db.String(64), comment="SHA-256 hash of this entry's data + previous_hash")
    previous_hash = db.Column(db.String(64), comment="row_hash of the preceding audit log entry")

    def __repr__(self):
        return f"<AuditLog {self.action} {self.table_name}/{self.record_id}>"
