# CLAUDE.md — MGCompliance

This file provides guidance to AI coding agents when working with code in this repository.

## Overview

**MGCompliance** is a self-contained, white-label SOC 2 trust portal and compliance management system. It runs as a standalone Docker deployment on any hosting provider — no cloud-specific dependencies required.

## Tech Stack

- **Backend:** Python 3.12 / Flask 3.1
- **Database:** PostgreSQL 17 via SQLAlchemy + Alembic migrations (auto-migrate on startup)
- **Frontend:** Flask/Jinja2 templates
- **API Docs:** Flasgger (OpenAPI 3.0 + Swagger UI at `/apidocs/`)
- **Evidence Collection:** Optional — boto3 (AWS), requests (GitHub)
- **Deployment:** Docker-first, runs on any hosting provider

## Development

```bash
docker compose -f docker-compose.dev.yml up --build
```

The app runs on port **5100**.

## Project Structure

```
app/                  Flask application
  auth.py             API key authentication decorators
  models/             SQLAlchemy models (controls, policies, evidence, tests, decision log, team members)
  routes/             Route blueprints (portal, admin, api)
  services/           Business logic (evidence engine, compliance scoring, transcript ingest, team CRUD)
  templates/          Jinja2 templates
  static/             CSS/JS assets
cli/                  CLI tools (init command for loading compliance data)
  loaders/            Data file loaders (one per entity type, with other_data preservation)
  schemas/            JSON Schema documentation for each data file format
collectors/           Automated evidence collection scripts (AWS, GitHub) — both optional
decision-logs/        Session transcripts staged by SessionEnd hook (gitignored)
migrations/           Alembic database migrations (auto-run on container startup)
policies/             Markdown policy documents by TSC category
scripts/              Utility scripts (SessionEnd hook)
tests/                Unit tests (pytest)
```

## Key Conventions

- **White-label**: all branding is configured via environment variables (`PORTAL_COMPANY_NAME`, `PORTAL_BRAND_NAME`, `PORTAL_CONTACT_EMAIL`). No organization-specific values should be hardcoded.
- **Self-contained**: the app + PostgreSQL deploy as a single Docker Compose stack. No external service dependencies at runtime.
- **Evidence collectors are optional**: AWS and GitHub collectors gracefully skip when credentials are not configured. The app must always start and run without them.
- **Auto-migration**: database schema is applied automatically via `alembic upgrade head` on container startup. New model changes require a new Alembic migration.
- **Policies are markdown files** in `policies/` — versioned in git, rendered by the portal
- **Evidence artifacts** (screenshots, exports) go in `evidence-artifacts/` which is gitignored — only metadata/links are tracked in the database
- **Decision logs** (session transcripts) are uploaded directly to the portal via `POST /api/decision-log/upload`, or land in `decision-logs/` for batch ingest. The SessionEnd hook in `scripts/session-end-hook.sh` handles automatic upload with offline fallback.
- **Collectors** are idempotent scripts that can be run on a schedule to gather fresh evidence
- Port **5100** for the trust portal

## Authentication

All significant API endpoints and admin routes require API key authentication. Each team member (human or AI agent) gets a unique API key managed via the admin UI at `/admin/team`.

- **API key delivery:** `X-API-Key` header or `Authorization: Bearer <key>`
- **Public routes (no auth):** `/`, `/policies`, `/controls`, `/status`, `/api/health`, `/api/docs/`
- **Protected routes:** all other `/api/*` endpoints
- **Admin routes:** `/admin/*` — require API key AND `is_compliance_admin=True`
- **Team members:** tracked in `team_members` table with role (human/agent), email, and active status
- **Decision log uploads** record which team member submitted the transcript (`submitted_by` FK)

## API Documentation

All API endpoints are documented with OpenAPI 3.0 annotations (Flasgger). Interactive docs are served at `/api/docs/` and the raw spec at `/api/openapi.json`.

## Database Migrations

Migrations run automatically on startup. To create a new migration:

```bash
docker exec mgcompliance-dev alembic revision --autogenerate -m "Description"
```

## Testing

**Docker-only testing — no venv:** All tests MUST be run inside the Docker container via `docker exec mgcompliance-dev`. Do NOT create or use Python virtual environments (`venv`, `virtualenv`, `pipenv`, `conda`, etc.). There is no venv setup. Dependencies are managed inside the Docker image.

```bash
docker exec mgcompliance-dev pytest tests/ -v --cov=app
```

Target: >= 80% coverage. Mock all external services (AWS, GitHub).

## SOC 2 Trust Service Criteria

Policies and controls are organized by TSC category:
- **Security** (CC) — Common Criteria
- **Availability** (A) — System availability commitments
- **Confidentiality** (C) — Protection of confidential information
- **Privacy** (P) — Personal information handling (GDPR alignment)
- **Processing Integrity** (PI) — System processing accuracy

## Commit Style

- **Subject line**: short imperative verb phrase under ~72 chars (e.g., `Fix oversized content chunks`). Start with a verb: `Add`, `Fix`, `Update`.
- **Body** (for non-trivial changes): use markdown formatting with `## Problem`, `## Solution`, and `## Verified` sections to explain *why* the change was made, *what* was done, and *how* it was validated. If the change adds or modifies environment variables, note the impact in the body.
- **Trivial changes**: only typo corrections are considered trivial and may omit the body. All other changes deserve the full message format.
- **Issue tracking**: if your project uses a task board, append the relevant card/issue URL as the last line before `Co-Authored-By`.
- **Co-authorship**: when AI-assisted, end with `Co-Authored-By: <agent-name> <noreply@provider.com>` (e.g., `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`).

**CRITICAL INSTRUCTION:** If there is a discrepancy between CLAUDE.md and AGENTS.md, then it must be identified immediately and the user asked for repair instructions.

## Synchronization Rule

If both `AGENTS.md` and `CLAUDE.md` exist in this directory, they must be identical in content and updated together in the same commit. Do not allow them to drift.
