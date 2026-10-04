"""Runtime configuration, the portal secret, the runtime AWS role and logging."""

import io
import json
import logging

import boto3
import pytest
from moto import mock_aws

from app import runtime_config
from app.logging_config import CloudWatchLogsHandler, JsonFormatter
from app.runtime_config import ConfigurationError
from app.services import aws_session

GOOD_KEY = "k" * 48

CONFIG_VARS = (
    "PORTAL_ENV", "PORTAL_SECRET_ID", "SECRET_KEY", "DATABASE_URL", "DATABASE_HOST", "DATABASE_PORT",
    "DATABASE_NAME", "DATABASE_USER", "DATABASE_PASSWORD", "DATABASE_SSLMODE", "DATABASE_OWNER_URL",
    "DATABASE_OWNER_USER", "DATABASE_OWNER_PASSWORD", "BOOTSTRAP_TOKEN", "CLOUDWATCH_LOG_GROUP",
    "TRUSTED_PROXY_HOPS", "AWS_RUNTIME_ROLE_ARN", "AWS_RUNTIME_ROLE_EXTERNAL_ID", "GITHUB_TOKEN",
    "COLLECTOR_ENCRYPTION_KEYS", "LOG_LEVEL", "LOCAL_SOURCE_ROOTS", "AUDIT_WITNESS_BUCKET",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    runtime_config._reset_for_tests()
    aws_session.reset_for_tests()
    yield
    runtime_config._reset_for_tests()
    aws_session.reset_for_tests()


# ----- environment and validation -----

def test_portal_env_defaults_to_production(monkeypatch):
    assert runtime_config.portal_env() == "production"
    monkeypatch.setenv("PORTAL_ENV", "Development")
    assert runtime_config.portal_env() == "development"
    monkeypatch.setenv("PORTAL_ENV", "staging")
    with pytest.raises(ConfigurationError):
        runtime_config.portal_env()


@pytest.mark.parametrize("value", [None, "", "dev-secret-change-me", "change-me-to-a-random-string", "short"])
def test_production_refuses_weak_secret_key(value):
    with pytest.raises(ConfigurationError):
        runtime_config.validate_secret_key(value)


def test_development_accepts_any_secret_key(monkeypatch):
    monkeypatch.setenv("PORTAL_ENV", "development")
    runtime_config.validate_secret_key(None)
    runtime_config.validate_secret_key("x")
    runtime_config.validate_secret_key(GOOD_KEY)


def test_create_app_refuses_default_secret_in_production(monkeypatch):
    from app import create_app

    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    with pytest.raises(ConfigurationError):
        create_app()
    monkeypatch.setenv("SECRET_KEY", "dev-secret-change-me")
    with pytest.raises(ConfigurationError):
        create_app()


def test_create_app_production_settings(monkeypatch):
    from app import create_app

    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("SECRET_KEY", GOOD_KEY)
    app = create_app()
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["TRUSTED_PROXY_HOPS"] == 1
    assert app.config["MAX_CONTENT_LENGTH"] == 32 * 1024 * 1024
    assert type(app.wsgi_app).__name__ == "ProxyFix"


def test_trusted_proxy_hops(monkeypatch):
    assert runtime_config.trusted_proxy_hops() == 1
    monkeypatch.setenv("PORTAL_ENV", "development")
    assert runtime_config.trusted_proxy_hops() == 0
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "2")
    assert runtime_config.trusted_proxy_hops() == 2
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "-1")
    with pytest.raises(ConfigurationError):
        runtime_config.trusted_proxy_hops()
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "x")
    with pytest.raises(ConfigurationError):
        runtime_config.trusted_proxy_hops()


# ----- database URLs -----

def test_database_url_prefers_full_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://a:b@h/db")
    monkeypatch.setenv("DATABASE_HOST", "ignored")
    assert runtime_config.database_url() == "postgresql://a:b@h/db"


def test_database_url_from_components_escapes_and_requires_ssl(monkeypatch):
    monkeypatch.setenv("DATABASE_HOST", "db.internal")
    monkeypatch.setenv("DATABASE_NAME", "portal")
    monkeypatch.setenv("DATABASE_USER", "app")
    monkeypatch.setenv("DATABASE_PASSWORD", "p@ss/w:rd")
    url = runtime_config.database_url()
    assert url == "postgresql://app:p%40ss%2Fw%3Ard@db.internal:5432/portal?sslmode=require"
    monkeypatch.setenv("PORTAL_ENV", "development")
    assert runtime_config.database_url().endswith("sslmode=prefer")
    monkeypatch.setenv("DATABASE_SSLMODE", "verify-full")
    assert runtime_config.database_url().endswith("sslmode=verify-full")


def test_database_url_missing_in_production_is_an_error(monkeypatch):
    with pytest.raises(ConfigurationError):
        runtime_config.database_url()
    monkeypatch.setenv("PORTAL_ENV", "development")
    assert runtime_config.database_url() == runtime_config.DEFAULT_DEV_DATABASE_URL


def test_owner_and_migration_urls(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://app:pw@h/db")
    assert runtime_config.owner_database_url() is None
    assert runtime_config.migration_database_url() == "postgresql://app:pw@h/db"
    monkeypatch.setenv("DATABASE_HOST", "h")
    monkeypatch.setenv("DATABASE_NAME", "db")
    monkeypatch.setenv("DATABASE_OWNER_USER", "master")
    monkeypatch.setenv("DATABASE_OWNER_PASSWORD", "mpw")
    assert runtime_config.owner_database_url().startswith("postgresql://master:mpw@h:5432/db")
    assert runtime_config.migration_database_url().startswith("postgresql://master:")
    monkeypatch.setenv("DATABASE_OWNER_URL", "postgresql://o@h/db")
    assert runtime_config.owner_database_url() == "postgresql://o@h/db"


# ----- Secrets Manager secret -----

@mock_aws
def test_secret_fills_only_unset_allowed_keys(monkeypatch):
    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(Name="portal/app", SecretString=json.dumps({
        "SECRET_KEY": "from-secret-" + "x" * 40,
        "DATABASE_PASSWORD": "db-pw",
        "BOOTSTRAP_TOKEN": "boot",
        "AWS_ACCESS_KEY_ID": "must-not-override",
        "UNRELATED": "ignored",
        "GITHUB_TOKEN": "",
    }))
    monkeypatch.setenv("PORTAL_SECRET_ID", "portal/app")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "from-env")
    filled = runtime_config.load_runtime_environment()
    assert sorted(filled) == ["DATABASE_PASSWORD", "SECRET_KEY"]
    import os
    assert os.environ["SECRET_KEY"].startswith("from-secret-")
    assert os.environ["BOOTSTRAP_TOKEN"] == "from-env"
    assert os.environ["AWS_ACCESS_KEY_ID"] != "must-not-override"
    assert "UNRELATED" not in os.environ
    # Idempotent within a process.
    assert runtime_config.load_runtime_environment() == []
    monkeypatch.delenv("SECRET_KEY")
    monkeypatch.delenv("DATABASE_PASSWORD")


@mock_aws
def test_secret_must_be_a_json_object(monkeypatch):
    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(Name="bad", SecretString="not json")
    client.create_secret(Name="list", SecretString="[1, 2]")
    monkeypatch.setenv("PORTAL_SECRET_ID", "bad")
    with pytest.raises(ConfigurationError):
        runtime_config.load_runtime_environment()
    runtime_config._reset_for_tests()
    monkeypatch.setenv("PORTAL_SECRET_ID", "list")
    with pytest.raises(ConfigurationError):
        runtime_config.load_runtime_environment()


def test_no_secret_id_is_a_noop():
    assert runtime_config.load_runtime_environment() == []


# ----- runtime role -----

@mock_aws
def test_runtime_role_is_assumed_for_every_aws_call(monkeypatch):
    role_arn = "arn:aws:iam::123456789012:role/portal-runtime"
    monkeypatch.setenv("AWS_RUNTIME_ROLE_ARN", role_arn)
    monkeypatch.setenv("AWS_RUNTIME_ROLE_EXTERNAL_ID", "ext-123")
    session = aws_session.get_session()
    identity = session.client("sts").get_caller_identity()
    assert ":assumed-role/portal-runtime/" in identity["Arn"]
    # Credentials are shared and refreshable.
    creds = session.get_credentials()
    assert creds.method == "sts-assume-role"
    assert aws_session.get_session().get_credentials() is creds


@mock_aws
def test_runtime_role_used_to_read_the_secret(monkeypatch):
    boto3.client("secretsmanager", region_name="us-east-1").create_secret(
        Name="s", SecretString=json.dumps({"CLOUDWATCH_LOG_GROUP": "/portal"}))
    monkeypatch.setenv("AWS_RUNTIME_ROLE_ARN", "arn:aws:iam::123456789012:role/portal-runtime")
    monkeypatch.setenv("PORTAL_SECRET_ID", "s")
    assert runtime_config.load_runtime_environment() == ["CLOUDWATCH_LOG_GROUP"]
    monkeypatch.delenv("CLOUDWATCH_LOG_GROUP")


def test_without_runtime_role_the_default_chain_is_used():
    session = aws_session.get_session("eu-west-1")
    assert session.region_name == "eu-west-1"
    assert aws_session.runtime_role_arn() is None


@mock_aws
def test_refresher_passes_external_id():
    base = boto3.Session(region_name="us-east-1")
    refresh = aws_session.assume_role_refresher(
        base, "arn:aws:iam::123456789012:role/r", "ext", "sess", "us-east-1")
    metadata = refresh()
    assert set(metadata) == {"access_key", "secret_key", "token", "expiry_time"}


# ----- logging -----

def test_json_formatter_emits_one_json_object():
    record = logging.LogRecord("portal", logging.INFO, __file__, 1, "hello %s", ("world",), None)
    payload = json.loads(JsonFormatter().format(record))
    assert payload["message"] == "hello world"
    assert payload["level"] == "INFO"


@mock_aws
def test_cloudwatch_handler_ships_records():
    logs = boto3.client("logs", region_name="us-east-1")
    logs.create_log_group(logGroupName="/portal/test")
    handler = CloudWatchLogsHandler("/portal/test", stream_name="unit", flush_interval=3600, client=logs)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("portal.cloudwatch.test")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        logger.info("shipped message")
        logging.getLogger("botocore.test").info("never shipped")
        handler.emit(logging.LogRecord("botocore.x", logging.INFO, __file__, 1, "skip", (), None))
        handler.flush()
    finally:
        logger.removeHandler(handler)
        handler.close()
    events = logs.get_log_events(logGroupName="/portal/test", logStreamName="unit")["events"]
    messages = [json.loads(e["message"])["message"] for e in events]
    assert messages == ["shipped message"]


def test_cloudwatch_handler_never_raises_on_failure(capsys):
    class Broken:
        class exceptions:  # noqa: N801 - mimics the boto3 client attribute
            ResourceAlreadyExistsException = RuntimeError

        def create_log_stream(self, **kwargs):
            raise ValueError("no network")

    handler = CloudWatchLogsHandler("/g", stream_name="s", flush_interval=3600, client=Broken())
    handler.emit(logging.LogRecord("portal", logging.INFO, __file__, 1, "x", (), None))
    handler.flush()
    handler.close()
    assert handler.failures >= 1
    assert "failed to ship" in capsys.readouterr().err


class RecordingLogs:
    """Stands in for the CloudWatch Logs client and records every batch."""

    class exceptions:  # noqa: N801 - mimics the boto3 client attribute
        ResourceAlreadyExistsException = RuntimeError

    def __init__(self):
        self.batches = []

    def create_log_stream(self, **kwargs):
        return {}

    def put_log_events(self, **kwargs):
        self.batches.append([event["message"] for event in kwargs["logEvents"]])
        return {}


def _record(message):
    return logging.LogRecord("portal", logging.INFO, __file__, 1, message, (), None)


def test_cloudwatch_queue_is_capped_by_bytes_and_counts_drops(capsys):
    assert CloudWatchLogsHandler.MAX_QUEUE_BYTES == 16 * 1024 * 1024
    assert CloudWatchLogsHandler.MAX_QUEUE_EVENTS == 50_000
    logs = RecordingLogs()
    handler = CloudWatchLogsHandler("/g", stream_name="s", flush_interval=3600, client=logs)
    handler.MAX_QUEUE_BYTES = 5 * (1000 + handler.EVENT_OVERHEAD)
    try:
        for i in range(8):
            handler.emit(_record(f"{i}" + "x" * 999))
        assert handler.dropped == 3
        assert handler.queued_bytes == 5 * (1000 + handler.EVENT_OVERHEAD)
        handler.flush()
        assert [message[0] for message in logs.batches[0]] == ["0", "1", "2", "3", "4"]
        assert handler.queued_bytes == 0
        assert "dropped 3 event(s)" in capsys.readouterr().err

        handler.emit(_record("after the flush"))
        handler.flush()
        assert logs.batches[-1] == ["after the flush"]
        assert handler.dropped == 3
    finally:
        handler.close()


def test_cloudwatch_batches_keep_queue_order_when_a_record_overflows_a_batch():
    logs = RecordingLogs()
    handler = CloudWatchLogsHandler("/g", stream_name="s", flush_interval=3600, client=logs)
    handler.MAX_BATCH_BYTES = 2 * (100 + handler.EVENT_OVERHEAD)
    try:
        for i in range(5):
            handler.emit(_record(f"{i}" + "y" * 99))
        handler.flush()
    finally:
        handler.close()
    assert [[message[0] for message in batch] for batch in logs.batches] == [["0", "1"], ["2", "3"], ["4"]]
    assert handler.queued_bytes == 0


def test_cloudwatch_shipping_thread_survives_a_failed_flush(capsys):
    import time

    logs = RecordingLogs()
    handler = CloudWatchLogsHandler("/g", stream_name="s", flush_interval=0.02, client=logs)
    real_drain = handler._drain
    failures = []

    def drain_once_broken():
        if not failures:
            failures.append(1)
            raise RuntimeError("drain broke")
        return real_drain()

    handler._drain = drain_once_broken
    try:
        handler.emit(_record("first"))
        deadline = time.monotonic() + 5
        while not any("first" in batch for batch in logs.batches) and time.monotonic() < deadline:
            time.sleep(0.02)
        handler.emit(_record("second"))
        while not any("second" in batch for batch in logs.batches) and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        handler.close()
    assert failures == [1]
    assert any("second" in batch for batch in logs.batches)
    assert "drain broke" in capsys.readouterr().err


@mock_aws
def test_configure_logging_attaches_cloudwatch_when_configured(monkeypatch):
    from app import logging_config

    boto3.client("logs", region_name="us-east-1").create_log_group(logGroupName="/portal/cfg")
    monkeypatch.setenv("CLOUDWATCH_LOG_GROUP", "/portal/cfg")
    monkeypatch.setenv("PORTAL_ENV", "development")
    stream = io.StringIO()
    monkeypatch.setattr("sys.stdout", stream)
    logging_config.configure_logging(force=True)
    try:
        root = logging.getLogger()
        assert any(isinstance(h, CloudWatchLogsHandler) for h in root.handlers)
        assert any(isinstance(h, CloudWatchLogsHandler)
                   for h in logging.getLogger("gunicorn.access").handlers)
    finally:
        logging_config.shutdown_logging()
        for name in ("", "gunicorn.access", "gunicorn.error"):
            lg = logging.getLogger(name)
            for h in list(lg.handlers):
                if isinstance(h, CloudWatchLogsHandler) or getattr(h, "_portal_handler", False):
                    lg.removeHandler(h)
        logging_config._configured_pid = None


# ----- bootstrap token and local source roots -----

def test_short_bootstrap_token_refused_in_production(monkeypatch):
    runtime_config.validate_bootstrap_token(None)
    with pytest.raises(ConfigurationError, match="at least 32"):
        runtime_config.validate_bootstrap_token("short-token")
    runtime_config.validate_bootstrap_token("t" * 32)
    monkeypatch.setenv("PORTAL_ENV", "development")
    runtime_config.validate_bootstrap_token("short-token")


def test_create_app_refuses_short_bootstrap_token(monkeypatch):
    from app import create_app

    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("SECRET_KEY", GOOD_KEY)
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "too-short")
    with pytest.raises(ConfigurationError):
        create_app()


def test_local_source_roots_are_resolved(monkeypatch, tmp_path):
    assert runtime_config.local_source_roots() is None
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    monkeypatch.setenv("LOCAL_SOURCE_ROOTS", f"{tmp_path / 'link'}::/srv/evidence")
    assert runtime_config.local_source_roots() == [str((tmp_path / "real").resolve()), "/srv/evidence"]


def test_database_connections_time_out_and_keep_alive(monkeypatch):
    from app import create_app

    monkeypatch.setenv("SECRET_KEY", GOOD_KEY)
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@db.internal/portal")
    options = create_app().config["SQLALCHEMY_ENGINE_OPTIONS"]
    args = options["connect_args"]
    assert args["connect_timeout"] == 10 and args["keepalives"] == 1 and args["keepalives_idle"] == 30
    assert "statement_timeout" not in args["options"]  # the CLI and migrations are not statement-limited
    assert "-c tcp_keepalives_idle=30" in args["options"]
    serving = create_app(serving=True).config["SQLALCHEMY_ENGINE_OPTIONS"]["connect_args"]
    assert "-c statement_timeout=60000" in serving["options"]
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    assert "connect_args" not in create_app().config["SQLALCHEMY_ENGINE_OPTIONS"]
