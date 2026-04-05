"""AI Agent-First Trust Portal — Self-hosted trust portal for SOC 2 compliance."""

from flasgger import Swagger
from flask import Flask

from app.config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    from app.models import db
    db.init_app(app)

    from app.audit_middleware import register_audit_middleware
    with app.app_context():
        register_audit_middleware(db)

    from app.routes.portal import portal_bp
    from app.routes.admin import admin_bp
    from app.routes.api import api_bp
    from app.routes.crud import crud_bp

    app.register_blueprint(portal_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(crud_bp, url_prefix="/api")

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

    return app
