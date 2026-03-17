"""Application configuration."""

import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "postgresql://mgcompliance:password@localhost:5433/mgcompliance"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    PORTAL_COMPANY_NAME = os.environ.get("PORTAL_COMPANY_NAME", "Your Company")
    PORTAL_BRAND_NAME = os.environ.get("PORTAL_BRAND_NAME", "Your Brand")
    PORTAL_CONTACT_EMAIL = os.environ.get("PORTAL_CONTACT_EMAIL", "compliance@example.com")

    SWAGGER = {
        "title": "MGCompliance API",
        "description": "SOC 2 Trust Portal and Compliance Management API",
        "version": "1.0.0",
        "uiversion": 3,
        "specs_route": "/api/docs/",
        "openapi": "3.0.3",
    }


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
