"""Evidence collection orchestration service.

Coordinates the automated evidence collectors and records their
findings in the database.
"""

import uuid
from datetime import datetime, timezone

from app.models import db, Evidence


def record_evidence(test_record_id, evidence_type, description, url=None,
                    file_path=None, collector_name=None):
    """Record a piece of evidence against a test record."""
    evidence = Evidence(
        id=str(uuid.uuid4()),
        test_record_id=test_record_id,
        evidence_type=evidence_type,
        description=description,
        url=url,
        file_path=file_path,
        collector_name=collector_name,
        collected_at=datetime.now(timezone.utc),
    )
    db.session.add(evidence)
    db.session.commit()
    return evidence
