"""Evidence submission model."""

from datetime import datetime, timezone

from app.models import db


class Evidence(db.Model):
    __tablename__ = "evidence"

    id = db.Column(db.String(36), primary_key=True)
    test_record_id = db.Column(db.String(36), db.ForeignKey("test_records.id"), nullable=False)
    evidence_type = db.Column(
        db.String(50), nullable=False,
        comment="link, file, screenshot, automated"
    )
    url = db.Column(db.String(1000), comment="URL for link-type evidence")
    file_path = db.Column(db.String(500), comment="Path in evidence-artifacts/ for file-type evidence")
    file_data = db.Column(db.LargeBinary, comment="Binary file content stored directly in database")
    file_name = db.Column(db.String(255), comment="Original filename of uploaded evidence")
    file_mime_type = db.Column(db.String(100), comment="MIME type of uploaded file (e.g. image/png)")
    description = db.Column(db.Text)
    collected_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    collector_name = db.Column(db.String(100), comment="Name of the collector script, if automated")
    trustcloud_id = db.Column(db.String(36), comment="Original TrustCloud evidence ID")
    other_data = db.Column(db.JSON, server_default="{}", comment="Unmapped fields from data imports")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Evidence {self.evidence_type} for test {self.test_record_id}>"
