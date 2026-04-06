"""Tests for the record-execution and execution-history API endpoints."""

import base64

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db, Control, TestRecord, Evidence
from app.models.audit_log import AuditLog
from app.services import team_service


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_headers(app):
    with app.app_context():
        member = team_service.create_member("Test User", "test@test.com", "human")
        return {"X-API-Key": member.api_key}


@pytest.fixture
def test_record(app):
    with app.app_context():
        ctrl = Control(id="ctrl-1", name="Test Control", category="security")
        db.session.add(ctrl)
        tr = TestRecord(id="test-1", name="Test Record", control_id="ctrl-1")
        db.session.add(tr)
        db.session.commit()
        return "test-1"


class TestRecordExecution:
    def test_record_success(self, client, auth_headers, test_record):
        resp = client.post(f"/api/tests/{test_record}/record-execution", json={
            "outcome": "success",
            "finding": "All checks passed",
            "comment": "Reviewed by security team",
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["execution_status"] == "completed"
        assert data["execution_outcome"] == "success"
        assert data["status"] == "passed"
        assert data["finding"] == "All checks passed"
        assert data["comment"] == "Reviewed by security team"
        assert data["last_executed_at"] is not None

    def test_record_failure(self, client, auth_headers, test_record):
        resp = client.post(f"/api/tests/{test_record}/record-execution", json={
            "outcome": "failure",
            "finding": "MFA not enforced for 2 users",
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["execution_outcome"] == "failure"
        assert data["status"] == "failed"

    def test_missing_outcome(self, client, auth_headers, test_record):
        resp = client.post(f"/api/tests/{test_record}/record-execution", json={
            "finding": "Something",
        }, headers=auth_headers)
        assert resp.status_code == 400
        assert "outcome" in resp.get_json()["error"]

    def test_invalid_outcome(self, client, auth_headers, test_record):
        resp = client.post(f"/api/tests/{test_record}/record-execution", json={
            "outcome": "maybe",
        }, headers=auth_headers)
        assert resp.status_code == 400
        assert "success" in resp.get_json()["error"]

    def test_not_found(self, client, auth_headers):
        resp = client.post("/api/tests/nonexistent/record-execution", json={
            "outcome": "success",
        }, headers=auth_headers)
        assert resp.status_code == 404

    def test_requires_auth(self, client, test_record):
        resp = client.post(f"/api/tests/{test_record}/record-execution", json={
            "outcome": "success",
        })
        assert resp.status_code == 401

    def test_optional_fields(self, client, auth_headers, test_record):
        resp = client.post(f"/api/tests/{test_record}/record-execution", json={
            "outcome": "success",
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["execution_outcome"] == "success"
        assert data["status"] == "passed"
        assert data["evidence_created"] == 0

    def test_with_evidence(self, client, auth_headers, test_record, app):
        resp = client.post(f"/api/tests/{test_record}/record-execution", json={
            "outcome": "success",
            "finding": "All credentials verified in 1Password",
            "evidence": [
                {
                    "evidence_type": "screenshot",
                    "description": "1Password showing AWS credentials",
                    "url": "https://example.com/screenshot1.png",
                },
                {
                    "evidence_type": "screenshot",
                    "description": "1Password showing GitHub credentials",
                    "url": "https://example.com/screenshot2.png",
                },
            ],
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["execution_outcome"] == "success"
        assert data["evidence_status"] == "submitted"
        assert data["evidence_created"] == 2

        with app.app_context():
            evidence = Evidence.query.filter_by(test_record_id=test_record).all()
            assert len(evidence) == 2
            assert evidence[0].evidence_type == "screenshot"

    def test_evidence_missing_required_fields(self, client, auth_headers, test_record):
        resp = client.post(f"/api/tests/{test_record}/record-execution", json={
            "outcome": "success",
            "evidence": [{"url": "https://example.com"}],
        }, headers=auth_headers)
        assert resp.status_code == 400
        assert "evidence_type" in resp.get_json()["error"]

    def test_with_file_upload(self, client, auth_headers, test_record, app):
        file_content = b"This is a test PDF content"
        b64_data = base64.b64encode(file_content).decode("ascii")

        resp = client.post(f"/api/tests/{test_record}/record-execution", json={
            "outcome": "success",
            "finding": "Password manager audit verified",
            "evidence": [{
                "evidence_type": "file",
                "description": "Password manager export",
                "file_data": b64_data,
                "file_name": "1password-export.pdf",
                "file_mime_type": "application/pdf",
            }],
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["evidence_created"] == 1

        with app.app_context():
            ev = Evidence.query.filter_by(test_record_id=test_record).first()
            assert ev.file_data == file_content
            assert ev.file_name == "1password-export.pdf"
            assert ev.file_mime_type == "application/pdf"

    def test_invalid_base64(self, client, auth_headers, test_record):
        resp = client.post(f"/api/tests/{test_record}/record-execution", json={
            "outcome": "success",
            "evidence": [{
                "evidence_type": "file",
                "description": "Bad file",
                "file_data": "not-valid-base64!!!",
            }],
        }, headers=auth_headers)
        assert resp.status_code == 400
        assert "base64" in resp.get_json()["error"]


class TestExecutionHistory:
    def test_empty_history(self, client, auth_headers, test_record):
        resp = client.get(f"/api/tests/{test_record}/execution-history",
                          headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["test_id"] == test_record
        assert data["executions"] == []

    def test_history_after_execution(self, client, auth_headers, test_record, app):
        """Test that execution history returns audit log entries.

        Note: In the test environment (SQLite), PostgreSQL audit triggers
        don't fire. We insert audit log entries manually to verify the
        endpoint logic.
        """
        from datetime import datetime, timezone

        with app.app_context():
            entry1 = AuditLog(
                table_name="test_records",
                record_id=test_record,
                action="UPDATE",
                old_values={"status": "pending"},
                new_values={
                    "execution_status": "completed",
                    "execution_outcome": "failure",
                    "status": "failed",
                    "finding": "First run failed",
                    "last_executed_at": "2026-04-05T10:00:00",
                },
                changed_at=datetime(2026, 4, 5, 10, 0, 0, tzinfo=timezone.utc),
            )
            entry2 = AuditLog(
                table_name="test_records",
                record_id=test_record,
                action="UPDATE",
                old_values={"status": "failed"},
                new_values={
                    "execution_status": "completed",
                    "execution_outcome": "success",
                    "status": "passed",
                    "finding": "Fixed and re-tested",
                    "last_executed_at": "2026-04-05T11:00:00",
                },
                changed_at=datetime(2026, 4, 5, 11, 0, 0, tzinfo=timezone.utc),
            )
            db.session.add(entry1)
            db.session.add(entry2)
            db.session.commit()

        resp = client.get(f"/api/tests/{test_record}/execution-history",
                          headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        executions = data["executions"]
        assert len(executions) == 2
        assert executions[0]["execution_outcome"] == "success"
        assert executions[1]["execution_outcome"] == "failure"

    def test_history_not_found(self, client, auth_headers):
        resp = client.get("/api/tests/nonexistent/execution-history",
                          headers=auth_headers)
        assert resp.status_code == 404

    def test_history_limit(self, client, auth_headers, test_record):
        resp = client.get(f"/api/tests/{test_record}/execution-history?limit=1",
                          headers=auth_headers)
        assert resp.status_code == 200

    def test_history_requires_auth(self, client, test_record):
        resp = client.get(f"/api/tests/{test_record}/execution-history")
        assert resp.status_code == 401


class TestBatchRecordExecution:
    @pytest.fixture
    def multiple_tests(self, app):
        with app.app_context():
            ctrl = Control(id="ctrl-batch", name="Batch Control", category="security")
            db.session.add(ctrl)
            for i in range(3):
                tr = TestRecord(id=f"batch-test-{i}", name=f"Batch Test {i}", control_id="ctrl-batch")
                db.session.add(tr)
            db.session.commit()
            return ["batch-test-0", "batch-test-1", "batch-test-2"]

    def test_batch_all_succeed(self, client, auth_headers, multiple_tests):
        resp = client.post("/api/tests/batch-record-execution", json={
            "executions": [
                {"test_id": "batch-test-0", "outcome": "success", "finding": "OK"},
                {"test_id": "batch-test-1", "outcome": "failure", "finding": "Failed"},
                {"test_id": "batch-test-2", "outcome": "success"},
            ],
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["succeeded"] == 3
        assert data["failed"] == 0
        assert len(data["results"]) == 3

    def test_batch_partial_failure(self, client, auth_headers, multiple_tests):
        resp = client.post("/api/tests/batch-record-execution", json={
            "executions": [
                {"test_id": "batch-test-0", "outcome": "success"},
                {"test_id": "nonexistent", "outcome": "success"},
                {"test_id": "batch-test-1", "outcome": "invalid-outcome"},
            ],
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["succeeded"] == 1
        assert data["failed"] == 2
        assert data["results"][0]["status"] == "ok"
        assert data["results"][1]["status"] == "error"
        assert data["results"][2]["status"] == "error"

    def test_batch_empty_array(self, client, auth_headers):
        resp = client.post("/api/tests/batch-record-execution", json={
            "executions": [],
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["succeeded"] == 0
        assert data["failed"] == 0

    def test_batch_missing_executions(self, client, auth_headers):
        resp = client.post("/api/tests/batch-record-execution", json={}, headers=auth_headers)
        assert resp.status_code == 400

    def test_batch_requires_auth(self, client):
        resp = client.post("/api/tests/batch-record-execution", json={"executions": []})
        assert resp.status_code == 401

    def test_batch_with_evidence(self, client, auth_headers, multiple_tests, app):
        resp = client.post("/api/tests/batch-record-execution", json={
            "executions": [{
                "test_id": "batch-test-0",
                "outcome": "success",
                "finding": "Verified",
                "evidence": [{
                    "evidence_type": "link",
                    "description": "Scan report",
                    "url": "https://example.com/report",
                }],
            }],
        }, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["succeeded"] == 1

        with app.app_context():
            ev = Evidence.query.filter_by(test_record_id="batch-test-0").first()
            assert ev is not None
            assert ev.url == "https://example.com/report"


class TestBatchSubmitEvidence:
    @pytest.fixture
    def multiple_tests(self, app):
        with app.app_context():
            ctrl = Control(id="ctrl-bev", name="Batch Ev Control", category="security")
            db.session.add(ctrl)
            for i in range(2):
                tr = TestRecord(id=f"bev-test-{i}", name=f"Batch Ev Test {i}", control_id="ctrl-bev")
                db.session.add(tr)
            db.session.commit()
            return ["bev-test-0", "bev-test-1"]

    def test_batch_submit_multiple(self, client, auth_headers, multiple_tests, app):
        resp = client.post("/api/evidence/batch-submit", json={
            "evidence": [
                {"test_record_id": "bev-test-0", "evidence_type": "link", "description": "Report A", "url": "https://a.com"},
                {"test_record_id": "bev-test-1", "evidence_type": "link", "description": "Report B", "url": "https://b.com"},
            ],
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["succeeded"] == 2
        assert data["failed"] == 0

        with app.app_context():
            for tid in multiple_tests:
                test = db.session.get(TestRecord, tid)
                assert test.evidence_status == "submitted"

    def test_batch_partial_failure(self, client, auth_headers, multiple_tests):
        resp = client.post("/api/evidence/batch-submit", json={
            "evidence": [
                {"test_record_id": "bev-test-0", "evidence_type": "link", "description": "OK", "url": "https://a.com"},
                {"test_record_id": "nonexistent", "evidence_type": "link", "description": "Bad"},
            ],
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["succeeded"] == 1
        assert data["failed"] == 1

    def test_batch_with_file(self, client, auth_headers, multiple_tests, app):
        b64 = base64.b64encode(b"csv data here").decode("ascii")
        resp = client.post("/api/evidence/batch-submit", json={
            "evidence": [{
                "test_record_id": "bev-test-0",
                "evidence_type": "file",
                "description": "Export",
                "file_data": b64,
                "file_name": "export.csv",
                "file_mime_type": "text/csv",
            }],
        }, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["succeeded"] == 1

        with app.app_context():
            ev = Evidence.query.filter_by(test_record_id="bev-test-0").first()
            assert ev.file_data == b"csv data here"

    def test_batch_empty(self, client, auth_headers):
        resp = client.post("/api/evidence/batch-submit", json={"evidence": []}, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["succeeded"] == 0

    def test_batch_missing_evidence(self, client, auth_headers):
        resp = client.post("/api/evidence/batch-submit", json={}, headers=auth_headers)
        assert resp.status_code == 400

    def test_batch_requires_auth(self, client):
        resp = client.post("/api/evidence/batch-submit", json={"evidence": []})
        assert resp.status_code == 401


class TestEvidenceDownload:
    def test_download_file(self, client, auth_headers, test_record, app):
        file_content = b"PNG screenshot data here"
        with app.app_context():
            ev = Evidence(
                id="ev-dl-1",
                test_record_id=test_record,
                evidence_type="screenshot",
                description="Test screenshot",
                file_data=file_content,
                file_name="screenshot.png",
                file_mime_type="image/png",
            )
            db.session.add(ev)
            db.session.commit()

        resp = client.get("/api/evidence/ev-dl-1/download", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.data == file_content
        assert resp.content_type == "image/png"
        assert "screenshot.png" in resp.headers.get("Content-Disposition", "")

    def test_download_no_file(self, client, auth_headers, test_record, app):
        with app.app_context():
            ev = Evidence(
                id="ev-dl-2",
                test_record_id=test_record,
                evidence_type="link",
                description="A URL",
                url="https://example.com",
            )
            db.session.add(ev)
            db.session.commit()

        resp = client.get("/api/evidence/ev-dl-2/download", headers=auth_headers)
        assert resp.status_code == 404

    def test_download_not_found(self, client, auth_headers):
        resp = client.get("/api/evidence/nonexistent/download", headers=auth_headers)
        assert resp.status_code == 404

    def test_download_requires_auth(self, client, test_record, app):
        with app.app_context():
            ev = Evidence(
                id="ev-dl-3",
                test_record_id=test_record,
                evidence_type="file",
                description="Secret file",
                file_data=b"secret",
            )
            db.session.add(ev)
            db.session.commit()

        resp = client.get("/api/evidence/ev-dl-3/download")
        assert resp.status_code == 401


class TestEvidenceCrudFileUpload:
    def test_create_evidence_with_file(self, client, auth_headers, test_record, app):
        file_content = b"audit log export CSV data"
        b64_data = base64.b64encode(file_content).decode("ascii")

        resp = client.post("/api/evidence", json={
            "test_record_id": test_record,
            "evidence_type": "file",
            "description": "Audit log export",
            "file_data": b64_data,
            "file_name": "audit-export.csv",
            "file_mime_type": "text/csv",
        }, headers=auth_headers)
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["has_file"] is True
        assert data["file_name"] == "audit-export.csv"

        with app.app_context():
            ev = db.session.get(Evidence, data["id"])
            assert ev.file_data == file_content


class TestAdminEvidenceUI:
    @pytest.fixture
    def admin_session(self, app, client):
        with app.app_context():
            member = team_service.create_member(
                "Admin", "admin@test.com", "human", is_compliance_admin=True
            )
            with client.session_transaction() as sess:
                sess["api_key"] = member.api_key
            return member

    def test_evidence_page_loads(self, client, admin_session, test_record):
        resp = client.get("/admin/evidence")
        assert resp.status_code == 200
        assert b"Submit Evidence" in resp.data
        assert b"Recent Evidence" in resp.data

    def test_upload_file_via_form(self, client, admin_session, test_record, app):
        from io import BytesIO
        data = {
            "test_record_id": test_record,
            "evidence_type": "screenshot",
            "description": "Password manager screenshot",
            "file": (BytesIO(b"fake png data"), "screenshot.png"),
        }
        resp = client.post(
            "/admin/evidence/upload",
            data=data,
            content_type="multipart/form-data",
        )
        assert resp.status_code == 302  # redirect after success

        with app.app_context():
            ev = Evidence.query.filter_by(test_record_id=test_record).first()
            assert ev is not None
            assert ev.file_data == b"fake png data"
            assert ev.file_name == "screenshot.png"
            assert ev.description == "Password manager screenshot"

            test = db.session.get(TestRecord, test_record)
            assert test.evidence_status == "submitted"

    def test_download_via_admin(self, client, admin_session, test_record, app):
        with app.app_context():
            ev = Evidence(
                id="ev-admin-dl",
                test_record_id=test_record,
                evidence_type="file",
                description="Test file",
                file_data=b"admin download test",
                file_name="report.pdf",
                file_mime_type="application/pdf",
            )
            db.session.add(ev)
            db.session.commit()

        resp = client.get("/admin/evidence/ev-admin-dl/download")
        assert resp.status_code == 200
        assert resp.data == b"admin download test"
        assert "report.pdf" in resp.headers.get("Content-Disposition", "")
