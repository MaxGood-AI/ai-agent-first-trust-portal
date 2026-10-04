"""Runtime configuration: environment variables, the optional Secrets Manager
secret, and the database URLs derived from them.

The portal is configured by a small, fixed set of environment variables
(documented in README.md -> "Configuration reference"). In AWS the container
environment holds only the base credentials, the runtime role ARN and the id
of one Secrets Manager secret; every other value comes from that secret.

Precedence, for every variable in ``SECRET_CAPABLE_KEYS``:

1. a real environment variable, when set and non-empty;
2. the key of the same name in the JSON secret named by ``PORTAL_SECRET_ID``;
3. the built-in default.

``load_runtime_environment()`` copies secret values into ``os.environ`` (only
for keys not already set) so every component - Flask, Alembic, the CLI, the
collectors - reads one consistent environment. It is idempotent and is called
once per process by the app factory, the Alembic environment and the
container entrypoint.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from urllib.parse import quote

logger = logging.getLogger(__name__)

PRODUCTION = "production"
DEVELOPMENT = "development"
TEST = "test"
VALID_ENVIRONMENTS = {PRODUCTION, DEVELOPMENT, TEST}

# Keys that may be supplied by the Secrets Manager JSON secret. Any other key
# in the secret is ignored, so the secret can never override AWS credentials
# or process-level settings.
SECRET_CAPABLE_KEYS = (
    "SECRET_KEY",
    "DATABASE_URL",
    "DATABASE_HOST",
    "DATABASE_PORT",
    "DATABASE_NAME",
    "DATABASE_USER",
    "DATABASE_PASSWORD",
    "DATABASE_SSLMODE",
    "COLLECTOR_ENCRYPTION_KEYS",
    "COLLECTOR_ENCRYPTION_KEY",
    "BOOTSTRAP_TOKEN",
    "GITHUB_TOKEN",
    "CLOUDWATCH_LOG_GROUP",
    "AUDIT_WITNESS_BUCKET",
)

# Owner (migration) credentials are accepted only from the process environment
# of the migration step; they are never read from the runtime secret and are
# removed before the web server starts (entrypoint.sh).
OWNER_KEYS = ("DATABASE_OWNER_URL", "DATABASE_OWNER_USER", "DATABASE_OWNER_PASSWORD")

MIN_BOOTSTRAP_TOKEN_LENGTH = 32

# Values that must never be used as SECRET_KEY outside development and tests.
PLACEHOLDER_SECRET_KEYS = {
    "dev-secret-change-me",
    "change-me-to-a-random-string",
    "change-me",
    "changeme",
    "secret",
}
MIN_SECRET_KEY_LENGTH = 32

DEFAULT_DEV_DATABASE_URL = "postgresql://trust_portal:password@localhost:5433/trust_portal"

_load_lock = threading.Lock()
_loaded = False


class ConfigurationError(RuntimeError):
    """Raised when the runtime configuration is unusable."""


def portal_env() -> str:
    """Return the deployment environment: production (default), development or test."""
    value = (os.environ.get("PORTAL_ENV") or PRODUCTION).strip().lower()
    if value not in VALID_ENVIRONMENTS:
        raise ConfigurationError(
            f"PORTAL_ENV must be one of {sorted(VALID_ENVIRONMENTS)}, got {value!r}"
        )
    return value


def is_production() -> bool:
    return portal_env() == PRODUCTION


def env(name: str, default: str | None = None) -> str | None:
    """Read a variable, treating an empty string as unset."""
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def fetch_secret(secret_id: str) -> dict:
    """Fetch and parse the JSON secret through the runtime AWS session."""
    from app.services.aws_session import get_session

    client = get_session().client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_id)
    raw = response.get("SecretString")
    if raw is None:
        raise ConfigurationError(f"Secret {secret_id} has no SecretString (binary secrets are not supported)")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"Secret {secret_id} is not a JSON object") from exc
    if not isinstance(data, dict):
        raise ConfigurationError(f"Secret {secret_id} is not a JSON object")
    return data


def load_runtime_environment(force: bool = False) -> list[str]:
    """Fill unset secret-capable variables from the Secrets Manager secret.

    Returns the names of the variables that were filled (never their values).
    A no-op when ``PORTAL_SECRET_ID`` is unset.
    """
    global _loaded
    with _load_lock:
        if _loaded and not force:
            return []
        secret_id = env("PORTAL_SECRET_ID")
        filled: list[str] = []
        if secret_id:
            data = fetch_secret(secret_id)
            for key in SECRET_CAPABLE_KEYS:
                if env(key) is not None:
                    continue
                value = data.get(key)
                if value is None or str(value).strip() == "":
                    continue
                os.environ[key] = str(value)
                filled.append(key)
            logger.info("Loaded %d value(s) from the portal secret", len(filled))
        _loaded = True
        return filled


def _reset_for_tests() -> None:
    global _loaded
    _loaded = False


def _component_url(user: str | None, password: str | None) -> str | None:
    host = env("DATABASE_HOST")
    name = env("DATABASE_NAME")
    if not host or not name or not user:
        return None
    port = env("DATABASE_PORT", "5432")
    sslmode = env("DATABASE_SSLMODE", "require" if is_production() else "prefer")
    auth = quote(user, safe="")
    if password:
        auth += ":" + quote(password, safe="")
    return f"postgresql://{auth}@{host}:{port}/{quote(name, safe='')}?sslmode={quote(sslmode, safe='')}"


def database_url() -> str:
    """SQLAlchemy URL for the application role."""
    url = env("DATABASE_URL")
    if url:
        return url
    url = _component_url(env("DATABASE_USER"), env("DATABASE_PASSWORD"))
    if url:
        return url
    if portal_env() == PRODUCTION:
        raise ConfigurationError(
            "No database configured: set DATABASE_URL, or DATABASE_HOST, DATABASE_NAME, "
            "DATABASE_USER and DATABASE_PASSWORD (directly or in the portal secret)."
        )
    return DEFAULT_DEV_DATABASE_URL


def owner_database_url() -> str | None:
    """SQLAlchemy URL for the migration-owner role, or None in single-role mode."""
    url = env("DATABASE_OWNER_URL")
    if url:
        return url
    return _component_url(env("DATABASE_OWNER_USER"), env("DATABASE_OWNER_PASSWORD"))


def migration_database_url() -> str:
    """URL Alembic connects with: the owner role when configured, else the app role."""
    return owner_database_url() or database_url()


def validate_bootstrap_token(value: str | None) -> None:
    """Refuse a short BOOTSTRAP_TOKEN outside development/test (unset is fine)."""
    if portal_env() in (DEVELOPMENT, TEST) or not value:
        return
    if len(value) < MIN_BOOTSTRAP_TOKEN_LENGTH:
        raise ConfigurationError(
            f"BOOTSTRAP_TOKEN must be at least {MIN_BOOTSTRAP_TOKEN_LENGTH} characters")


TRUE_VALUES = {"1", "true", "yes", "on"}


def witness_disabled() -> bool:
    """``AUDIT_WITNESS_DISABLED`` - read from the process environment only (never
    from the runtime secret). When true, the audit chain head is never
    published, whatever ``AUDIT_WITNESS_BUCKET`` says."""
    return (os.environ.get("AUDIT_WITNESS_DISABLED") or "").strip().lower() in TRUE_VALUES


def local_source_roots() -> list[str] | None:
    """Directories local-directory git sources may read (``LOCAL_SOURCE_ROOTS``,
    separated by ``:``), resolved with realpath. None when unset."""
    import os.path

    raw = env("LOCAL_SOURCE_ROOTS")
    if not raw:
        return None
    return [os.path.realpath(part) for part in raw.split(":") if part.strip()]


def validate_secret_key(value: str | None) -> None:
    """Refuse a missing, short or placeholder SECRET_KEY outside development/test."""
    if portal_env() in (DEVELOPMENT, TEST):
        return
    if not value:
        raise ConfigurationError(
            "SECRET_KEY is not set. Set it in the environment or in the portal secret "
            f"(at least {MIN_SECRET_KEY_LENGTH} random characters)."
        )
    if value.strip().lower() in PLACEHOLDER_SECRET_KEYS or len(value) < MIN_SECRET_KEY_LENGTH:
        raise ConfigurationError(
            f"SECRET_KEY is a placeholder or shorter than {MIN_SECRET_KEY_LENGTH} characters; "
            "generate one with: python3 -c 'import secrets; print(secrets.token_urlsafe(48))'"
        )


def trusted_proxy_hops() -> int:
    default = "1" if is_production() else "0"
    raw = env("TRUSTED_PROXY_HOPS", default)
    try:
        hops = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"TRUSTED_PROXY_HOPS must be an integer, got {raw!r}") from exc
    if hops < 0:
        raise ConfigurationError("TRUSTED_PROXY_HOPS must be >= 0")
    return hops


# libpq connection settings for every portal connection: fail fast when the
# database is unreachable (10 s connect timeout), and detect half-open TCP
# connections (client keepalives after 30 s idle, every 10 s, 3 probes; a 30 s
# TCP user timeout for unacknowledged data).
DB_CONNECT_ARGS = {
    "connect_timeout": 10,
    "keepalives": 1,
    "keepalives_idle": 30,
    "keepalives_interval": 10,
    "keepalives_count": 3,
    "tcp_user_timeout": 30_000,
}
# Server-side session settings of every portal connection: the server probes
# an idle client the same way, so it ends the session of a vanished process -
# releasing its locks, the audit chain lock included - within about a minute.
DB_SESSION_SETTINGS = {
    "tcp_keepalives_idle": "30",
    "tcp_keepalives_interval": "10",
    "tcp_keepalives_count": "3",
}
# Longest statement a web request may run (gunicorn workers only; migrations
# and the CLI are not limited).
WEB_STATEMENT_TIMEOUT_MS = 60_000


def engine_options(url: str, *, serving: bool = False) -> dict:
    """SQLAlchemy engine options for the portal's database engine.

    PostgreSQL connections get ``DB_CONNECT_ARGS`` and, as startup options,
    ``DB_SESSION_SETTINGS`` (plus ``statement_timeout`` when ``serving``),
    appended to any ``options`` the database URL already carries.
    """
    options = {"pool_pre_ping": True, "pool_recycle": 1800}
    if url.startswith("postgresql"):
        from sqlalchemy.engine import make_url

        settings = dict(DB_SESSION_SETTINGS)
        if serving:
            settings["statement_timeout"] = str(WEB_STATEMENT_TIMEOUT_MS)
        startup = " ".join(f"-c {name}={value}" for name, value in settings.items())
        existing = make_url(url).query.get("options")
        if isinstance(existing, tuple):
            existing = " ".join(existing)
        options["connect_args"] = {**DB_CONNECT_ARGS,
                                   "options": f"{existing} {startup}" if existing else startup}
    return options


def settings_from_env() -> dict:
    """Flask settings derived from the environment (called at app creation)."""
    production = is_production()
    secret_key = env("SECRET_KEY")
    validate_secret_key(secret_key)
    validate_bootstrap_token(env("BOOTSTRAP_TOKEN"))
    return {
        "PORTAL_ENV": portal_env(),
        "PORTAL_VERSION": env("PORTAL_VERSION", "dev"),
        "SECRET_KEY": secret_key or "dev-secret-change-me",
        "SQLALCHEMY_DATABASE_URI": database_url(),
        "SQLALCHEMY_ENGINE_OPTIONS": engine_options(database_url()),
        "PORTAL_COMPANY_NAME": env("PORTAL_COMPANY_NAME", "Your Company"),
        "PORTAL_BRAND_NAME": env("PORTAL_BRAND_NAME", "Your Brand"),
        "PORTAL_CONTACT_EMAIL": env("PORTAL_CONTACT_EMAIL", "compliance@example.com"),
        "SESSION_COOKIE_SECURE": production,
        "TRUSTED_PROXY_HOPS": trusted_proxy_hops(),
        "BOOTSTRAP_TOKEN": env("BOOTSTRAP_TOKEN"),
    }
