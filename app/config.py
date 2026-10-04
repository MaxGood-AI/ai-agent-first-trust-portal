"""Static Flask configuration.

Environment-dependent settings (secret key, database URL, branding, proxy
trust) are computed at app creation by ``app.runtime_config.settings_from_env``
so that values loaded from the portal secret are honoured. The classes here
hold only fixed, opinionated defaults.
"""

from datetime import timedelta

# The largest request body any route accepts (routes raised in app.request_limits).
MAX_REQUEST_BYTES = 32 * 1024 * 1024
# The body limit of every other route (see app.request_limits).
REQUEST_BODY_LIMIT_BYTES = 1024 * 1024


class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 1800}

    MAX_CONTENT_LENGTH = MAX_REQUEST_BYTES
    REQUEST_BODY_LIMIT = REQUEST_BODY_LIMIT_BYTES
    # Urlencoded bodies and each multipart text field; fields or parts per form.
    MAX_FORM_MEMORY_SIZE = 500_000
    MAX_FORM_PARTS = 1000

    SESSION_COOKIE_NAME = "tp_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    # A browser session ends this long after login, however active it is.
    SESSION_ABSOLUTE_LIFETIME = timedelta(hours=12)

    CSRF_ENABLED = True
    # /api/health reports 503 until the database schema is at the migration head.
    HEALTH_REQUIRE_SCHEMA_HEAD = True
    # Failed-authentication budget per client IP and bucket: attempts per window.
    AUTH_RATE_LIMIT_ATTEMPTS = 10
    AUTH_RATE_LIMIT_WINDOW_SECONDS = 900

    SWAGGER = {
        "title": "Trust Portal API",
        "description": "SOC 2 Trust Portal and Compliance Management API",
        "version": "1.0.0",
        "uiversion": 3,
        "specs_route": "/api/docs/",
        "openapi": "3.0.3",
    }


class TestConfig(Config):
    TESTING = True
    PORTAL_ENV = "test"
    PORTAL_VERSION = "test"
    SECRET_KEY = "test-secret-key-0123456789abcdefghijklmnop"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {}
    SESSION_COOKIE_SECURE = False
    TRUSTED_PROXY_HOPS = 0
    BOOTSTRAP_TOKEN = None
    HEALTH_REQUIRE_SCHEMA_HEAD = False
    PORTAL_COMPANY_NAME = "Your Company"
    PORTAL_BRAND_NAME = "Your Brand"
    PORTAL_CONTACT_EMAIL = "compliance@example.com"
