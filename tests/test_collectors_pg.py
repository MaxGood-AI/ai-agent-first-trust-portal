"""Collectors that read the portal database end their read transaction before
slow work (HTTP probes), so no table lock is held while they wait."""

import threading
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from app.models import Vendor, db
from collectors.vendor_check_collector import VendorCollector


def test_vendor_probes_run_without_an_open_transaction(pg_app):
    db.session.add(Vendor(id=str(uuid.uuid4()), name="Acme", status="active",
                          security_page_url="https://security.example.com"))
    db.session.commit()
    config = SimpleNamespace(config={"probe_urls": True}, name="vendor", id="cfg",
                             credential_mode="none", encrypted_credentials=None)
    in_probe, release = threading.Event(), threading.Event()
    results = {}

    def slow_get(url, timeout=None, **kwargs):
        in_probe.set()
        release.wait(10)
        return SimpleNamespace(status_code=200, url=url)

    def runner():
        with pg_app.app_context():
            try:
                results["checks"] = VendorCollector(config=config, resolver=None).run()
            finally:
                db.session.remove()

    observer = create_engine(db.engine.url, poolclass=NullPool, isolation_level="AUTOCOMMIT")
    with patch("app.services.safe_http.safe_get", side_effect=slow_get):
        thread = threading.Thread(target=runner)
        thread.start()
        assert in_probe.wait(10)
        with observer.connect() as conn:
            idle = conn.execute(text(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                "AND state = 'idle in transaction' AND pid <> pg_backend_pid()")).scalar()
            conn.execute(text("SET lock_timeout = '2s'"))
            conn.execute(text("ALTER TABLE vendors ADD COLUMN probe_marker integer"))
        release.set()
        thread.join(10)
    observer.dispose()
    assert idle == 0
    assert any(check.check_name.startswith("vendor_security_page_reachable") for check in results["checks"])
