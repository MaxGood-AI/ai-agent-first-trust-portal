"""Audit witness state: arming (owner-only, audited) and head publications."""

from app.models import db


class AuditWitnessArming(db.Model):
    """One row per arming of the audit witness; the witness publishes only once armed.

    Written only by ``audit_witness_arm(note)`` (owner-only SECURITY DEFINER
    function, migration 020); a guard trigger refuses every other write.
    """

    __tablename__ = "audit_witness_arming"

    id = db.Column(db.Integer, primary_key=True)
    armed_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=db.func.now())
    armed_by = db.Column(db.String(128), nullable=False, comment="Database role that armed the witness")
    note = db.Column(db.String(500), nullable=True)


class AuditWitnessPublication(db.Model):
    """One row per chain-head publication that reached the witness bucket."""

    __tablename__ = "audit_witness_publications"

    id = db.Column(db.Integer, primary_key=True)
    published_at = db.Column(db.DateTime(timezone=True), nullable=False)
    head_id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"), nullable=False)
    row_hash = db.Column(db.String(64), nullable=False)
    object_key = db.Column(db.String(512), nullable=False)
    outcome = db.Column(db.String(16), nullable=False, comment="published | already | conflict")

    __table_args__ = (db.Index("ix_audit_witness_publications_published_at", "published_at"),)
