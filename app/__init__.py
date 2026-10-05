"""AI Agent-First Trust Portal — Self-hosted trust portal for SOC 2 compliance."""

from flasgger import Swagger
from flask import Flask

from app.config import Config


def create_app(config_class=None, *, serving=False):
    """Create the Flask application.

    Without ``config_class`` the app is configured from the environment and
    the optional portal secret (see ``app.runtime_config``); startup is
    refused on an unsafe configuration. Tests pass ``TestConfig``.

    The background scheduler is not started here: gunicorn workers start it
    (``gunicorn.conf.py``), so migrations, the CLI and tests never run jobs.
    ``serving=True`` (the gunicorn entry point) also limits each database
    statement to ``WEB_STATEMENT_TIMEOUT_MS``.
    """
    testing = bool(config_class is not None and getattr(config_class, "TESTING", False))

    app = Flask(__name__)
    app.config.from_object(Config)
    if not testing:
        from app.logging_config import configure_logging
        from app.runtime_config import load_runtime_environment, settings_from_env

        load_runtime_environment()
        configure_logging()
        settings = settings_from_env()
        if serving:
            from app.runtime_config import engine_options

            settings["SQLALCHEMY_ENGINE_OPTIONS"] = engine_options(
                settings["SQLALCHEMY_DATABASE_URI"], serving=True)
        app.config.from_mapping(settings)
        from app.runtime_config import is_production, witness_disabled

        if witness_disabled() and is_production():
            import logging

            logging.getLogger(__name__).warning(
                "AUDIT_WITNESS_DISABLED is set: the audit chain head is not published to the "
                "witness bucket. Use this only for a database whose audit chain will be discarded.")
    if config_class is not None:
        app.config.from_object(config_class)

    from app.request_limits import check_route_limits, register_request_limits
    register_request_limits(app)

    from app.models import db
    db.init_app(app)

    from app.audit_middleware import register_audit_middleware
    with app.app_context():
        register_audit_middleware(db)

    from app.security import register_security
    register_security(app)

    from app.services.audit_chain import redact_values
    from app.services.audit_witness import witness_status_for_display
    app.jinja_env.filters["redact_audit"] = redact_values
    app.jinja_env.globals["witness_status"] = witness_status_for_display

    from app.routes.portal import portal_bp
    from app.routes.admin import admin_bp
    from app.routes.api import api_bp
    from app.routes.crud import crud_bp
    from app.routes.collectors_api import collectors_api_bp
    from app.routes.setup import setup_bp
    from app.routes.git_sources_api import git_sources_api_bp
    from app.routes.admin_git import admin_git_bp
    from app.routes.admin_store import admin_store_bp
    from app.routes.evidence_store_api import evidence_store_api_bp

    app.register_blueprint(portal_bp)
    app.register_blueprint(setup_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(admin_git_bp, url_prefix="/admin")
    app.register_blueprint(admin_store_bp, url_prefix="/admin")
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(crud_bp, url_prefix="/api")
    app.register_blueprint(collectors_api_bp, url_prefix="/api")
    app.register_blueprint(git_sources_api_bp, url_prefix="/api")
    app.register_blueprint(evidence_store_api_bp, url_prefix="/api")
    check_route_limits(app)

    Swagger(app, template={
        "info": {
            "title": app.config["SWAGGER"]["title"],
            "description": app.config["SWAGGER"]["description"],
            "version": app.config["SWAGGER"]["version"],
        },
        "basePath": "/api",
    })

    @app.context_processor
    def inject_portal_settings():
        from app.services.settings_service import get_portal_settings
        return {"portal": get_portal_settings()}

    @app.context_processor
    def inject_tooltips():
        from app.tooltip_definitions import TOOLTIPS
        return {"tooltips": TOOLTIPS}

    return app
