# AI Agent-First Trust Portal

### Let AI Agents Get You to SOC 2 Type 2 Compliance!

A self-contained, white-label **SOC 2 trust portal and compliance management system** designed to be driven by AI agents. Deploy with a single `docker compose up`, point your AI agents at the API, and let them manage your compliance program — collecting evidence, recording test results, tracking controls, and maintaining your audit trail.

Built for small teams that use **Claude Code**, **Codex**, or other AI coding agents as part of their development workflow. The portal provides the structure; your AI agents do the work.

**No compliance expertise required to get started.** The system ships with SOC 2 policy templates, automated evidence collectors, and an API designed for agent-first workflows — not clickthrough GUIs.

## Features

### Agent-First Compliance
- **Full API for AI agents** — Every compliance operation (record test results, submit evidence, upload files, verify audit integrity) is available via REST API with API key auth
- **Batch operations** — Record execution results and submit evidence for multiple tests in a single call
- **Decision Log** — Automatically ingest AI agent session transcripts (Claude Code, Codex) as formal compliance audit trail
- **Tamper-evident audit log** — SHA-256 hash chain on every compliance data change, with a verification endpoint to prove integrity
- **Claude Code skill** — Companion [trust-portal skill](https://github.com/MaxGood-AI/ai-agent-first-trust-portal-skill) provides CLI commands for all API operations

### Compliance Management
- **Control & Test Tracking** — Database-backed SOC 2 controls, tests, and evidence with pass/fail execution recording
- **Evidence file storage** — Upload evidence files (screenshots, exports, PDFs) directly to the database via API or admin UI
- **Automated Evidence Collection** — Optional collectors for AWS infrastructure (20+ checks) and GitHub repositories
- **Policy Library** — Version-controlled markdown policies organized by Trust Service Criteria category
- **Governance Templates** — Ready-to-use CLAUDE.md and AGENTS.md templates for AI agent SOC 2 compliance

### Trust Portal
- **Public-facing portal** — Client-facing pages showing compliance status, policies, controls, systems, vendors, and risks
- **Admin Dashboard** — Manage compliance artifacts, review evidence gaps, upload evidence with file picker
- **Interactive API Documentation** — OpenAPI 3.0 spec with Swagger UI at `/api/docs/`
- **White-Label** — Fully customizable branding via environment variables
- **Self-Contained** — App + PostgreSQL in a single Docker Compose stack, deploys anywhere

## Quick Start

```bash
git clone <your-repo-url> trust-portal
cd trust-portal
cp .env.example .env
# Edit .env with your organization's branding and credentials
docker compose up --build
```

The trust portal is available at `http://localhost:5100` and the API docs at `http://localhost:5100/api/docs/`.

That's it. The database schema is created automatically on first startup.

## Architecture

- **Backend:** Python 3.12 / Flask 3.1
- **Database:** PostgreSQL 17 / SQLAlchemy + Alembic (auto-migrates on startup)
- **Frontend:** Jinja2 templates
- **API Docs:** Flasgger (OpenAPI 3.0 + Swagger UI)
- **Evidence Collection:** Python + boto3 (AWS), requests (GitHub) — both optional
- **Container:** Docker with gunicorn (production) or Flask dev server (development)

## Configuration

All configuration is via environment variables (see `.env.example` for the complete list):

### Required

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask session secret key | `dev-secret-change-me` |

### Portal Branding

| Variable | Description | Default |
|----------|-------------|---------|
| `PORTAL_COMPANY_NAME` | Legal entity name shown in footer | `Your Company` |
| `PORTAL_BRAND_NAME` | Brand name shown in header/navigation | `Your Brand` |
| `PORTAL_CONTACT_EMAIL` | Compliance contact email | `compliance@example.com` |

### Database

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string (for external DB) | Set automatically by docker-compose |
| `POSTGRES_DB` | Database name (docker-compose) | `trust_portal` |
| `POSTGRES_USER` | Database user (docker-compose) | `trust_portal` |
| `POSTGRES_PASSWORD` | Database password (docker-compose) | `trust_portal` |
| `PORT` | Host port mapping | `5100` |

### AWS Evidence Collection (Optional)

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS region for evidence collection | `us-east-1` |
| `AWS_ACCESS_KEY_ID` | AWS access key | (empty — collection disabled) |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key | (empty — collection disabled) |

### GitHub Evidence Collection (Optional)

| Variable | Description | Default |
|----------|-------------|---------|
| `GITHUB_TOKEN` | GitHub personal access token | (empty — collection disabled) |
| `GITHUB_ORG` | GitHub organization name | (empty) |
| `GITHUB_API_URL` | GitHub API base URL | `https://api.github.com` |
| `GITHUB_REPOS` | Comma-separated list of repos to monitor | (empty) |

## API Documentation

Interactive API documentation is served at `/api/docs/` (Swagger UI) and the raw OpenAPI spec at `/api/openapi.json`.

### Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check with database connectivity |
| `/api/compliance-score` | GET | Overall and per-category compliance scores |
| `/api/gaps` | GET | Tests with missing or outdated evidence |
| `/api/tests/<id>/record-execution` | POST | Record a test execution result (with optional evidence + file uploads) |
| `/api/tests/<id>/execution-history` | GET | Execution history for a test (from audit log) |
| `/api/tests/batch-record-execution` | POST | Record results for multiple tests at once |
| `/api/evidence/batch-submit` | POST | Submit evidence to multiple tests at once |
| `/api/evidence/<id>/download` | GET | Download an evidence file |
| `/api/audit-log` | GET | Query compliance data change history |
| `/api/audit-log/verify` | GET | Verify audit log hash chain integrity |
| `/api/decision-log/upload` | POST | Upload a session transcript |
| `/api/decision-log/sessions` | GET | List ingested decision log sessions |
| `/api/settings` | GET/PUT | Portal configuration |

CRUD endpoints (GET, POST, PUT, DELETE) are available for: `/api/controls`, `/api/tests`, `/api/evidence`, `/api/policies`, `/api/systems`, `/api/vendors`, `/api/risks`, `/api/pentest-findings`.

Full interactive documentation at `/api/docs/` (Swagger UI).

## Project Structure

```
app/                      Flask application
  models/                 SQLAlchemy models (controls, policies, evidence, tests, decision log, audit log)
  routes/                 Route blueprints (portal, admin, api, crud)
  services/               Business logic (compliance scoring, evidence recording, transcript ingest)
  templates/              Jinja2 templates (admin dashboard, public portal)
  static/                 CSS/JS assets
cli/                      CLI tools (init + export commands)
  loaders/                Data file loaders (one per entity type)
  schemas/                JSON Schema documentation for each data file format
collectors/               Automated evidence collection scripts
  aws_collector.py        20+ AWS checks: IAM MFA, RDS, S3, CloudTrail, Lambda, KMS, GuardDuty...
  github_collector.py     Branch protection, PR review evidence (requires GitHub token)
  base_collector.py       Abstract base class for custom collectors
decision-logs/            Session transcripts staged for ingestion (gitignored)
migrations/               Alembic database migrations (auto-run on startup)
  versions/               Sequential migration scripts (001-014)
templates/governance/     AI agent governance document templates
  CLAUDE.md.template      Template for Claude Code governance
  AGENTS.md.template      Template for all AI agents (includes Codex Review Protocol)
  GOVERNANCE-SETUP.md     Step-by-step setup instructions
tests/                    Unit tests (pytest, 320+ tests, 80%+ coverage)
```

> **Note:** Policy markdown files are stored externally in your compliance data directory and loaded via `cli init`. Set the `POLICY_DIR` environment variable to point at your policy files for the portal to render them.

## Loading Compliance Data

The trust portal loads organization-specific data from an external directory via the `cli init` command. Your data directory should contain JSON files following the schemas in `cli/schemas/`.

### Data Directory Structure

```
your-data-dir/
├── controls.json              # SOC 2 controls
├── tests.json                 # Test definitions linked to controls
├── systems.json               # System inventory (requires System model)
├── vendors.json               # Vendor inventory (requires Vendor model)
├── policy-index.json          # Policy metadata
├── risk-register.json         # Risk register (requires RiskRegister model)
└── evidence/
    └── evidence-index.json    # Evidence submission metadata
```

### Running the Init Command

```bash
# Development: set COMPLIANCE_DATA_DIR in .env, then:
docker exec trust-portal-dev python -m cli.init --data-dir /data

# Or pass any path directly:
docker exec trust-portal-dev python -m cli.init --data-dir /path/to/data

# Dry run (preview without writing):
docker exec trust-portal-dev python -m cli.init --data-dir /data --dry-run

# Verbose output:
docker exec trust-portal-dev python -m cli.init --data-dir /data -v
```

The init command is **idempotent** — running it multiple times produces identical database state. Fields that don't map to model columns are preserved in each record's `other_data` JSON column, so no source data is ever discarded.

### Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `COMPLIANCE_DATA_DIR` | Path to your data directory (for Docker volume mount) | (none — must be set explicitly) |

## Development

```bash
cp .env.example .env
# Set COMPLIANCE_DATA_DIR to point to your data directory
docker compose -f docker-compose.dev.yml up --build
```

The dev server runs with hot-reload on port 5100. PostgreSQL is on port 5433 (avoids conflicts with other services).

### Running Tests

```bash
docker exec trust-portal-dev pytest tests/ -v --cov=app
```

Target: >= 80% coverage. All external services (AWS, GitHub) are mocked in tests.

### Database Migrations

Migrations run automatically on container startup. To create a new migration after model changes:

```bash
docker exec trust-portal-dev alembic revision --autogenerate -m "Description of change"
```

## Evidence Collection

### AWS Collector

Gathers evidence from your AWS infrastructure:
- **IAM MFA** — checks that all IAM users have MFA enabled
- **RDS Encryption** — verifies encryption-at-rest on database instances
- **RDS Backups** — checks backup retention configuration
- **Security Groups** — flags overly permissive rules (0.0.0.0/0)

Set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION` to enable.

### GitHub Collector

Gathers evidence from your GitHub repositories:
- **Branch Protection** — checks main branch protection rules
- **PR Reviews** — verifies recent PRs have been reviewed before merging

Set `GITHUB_TOKEN`, `GITHUB_ORG`, and `GITHUB_REPOS` (comma-separated list) to enable.

### Writing Custom Collectors

Extend `collectors/base_collector.py`:

```python
from collectors.base_collector import BaseCollector

class MyCollector(BaseCollector):
    def __init__(self):
        super().__init__("my-source")

    def collect(self):
        return [{
            "test_name": "Name matching a test record",
            "evidence_type": "automated",
            "description": "What the evidence shows",
            "url": "https://link-to-source",
            "file_path": None,
        }]
```

## AI Agent Governance Templates

Trust Portal ships with template governance documents that establish the SOC 2 evidence chain for any organization using Claude Code + Codex.

**Location:** `templates/governance/`

| File | Purpose |
|------|---------|
| `CLAUDE.md.template` | Governance for Claude Code — conventions, evidence chain, workflows |
| `AGENTS.md.template` | Governance for all AI agents — same as above + Codex Review Protocol |
| `GOVERNANCE-SETUP.md` | Step-by-step instructions for setting up governance in your dev environment |

These templates are designed to be copied into the root of your organization's development directory (the parent directory containing all your repos). They include placeholder sections (`{{ VARIABLE }}` and `<!-- CUSTOMIZE -->` blocks) for organization-specific content, while the SOC 2 compliance framework sections are ready to use as-is.

See `templates/governance/GOVERNANCE-SETUP.md` for the full setup guide.

## Decision Log Integration

Trust Portal can ingest AI agent session transcripts as formal compliance audit evidence.

### How It Works

1. **Claude Code SessionEnd hook** copies session transcripts to `decision-logs/`
2. `POST /api/decision-log/ingest` parses the JSONL files and stores them in PostgreSQL
3. The system automatically detects "done." verification acknowledgments (formal smoke test sign-offs)
4. Sessions, entries, and verifications are queryable via the API

### The "done." Protocol

When an AI agent presents completed work and asks a human to verify:
- The human responding **"done."** means they have tested the changes and smoke-tested likely regression areas
- This is captured in the session transcript and automatically flagged as a formal testing acknowledgment
- No additional test documentation is required — the transcript provides full context

## SOC 2 Trust Service Criteria

Controls and policies are organized by SOC 2 TSC category:

| Category | Description |
|----------|-------------|
| Security | Common Criteria (CC) |
| Availability | System availability commitments |
| Confidentiality | Protection of confidential information |
| Privacy | Personal information handling (GDPR alignment) |
| Processing Integrity | System processing accuracy |

## Deployment on Any VPS

Trust Portal runs on any server with Docker and Docker Compose installed. No cloud-specific services are required.

### Basic Deployment

```bash
# On your server
git clone <your-repo-url> /opt/trust-portal
cd /opt/trust-portal
cp .env.example .env
# Edit .env: set SECRET_KEY, branding, and optional collector credentials
docker compose up -d
```

### SSL/TLS

For production, place a reverse proxy in front of Trust Portal:

**Caddy** (automatic HTTPS):
```
compliance.yourdomain.com {
    reverse_proxy localhost:5100
}
```

**nginx**:
```nginx
server {
    listen 443 ssl;
    server_name compliance.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:5100;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Connecting to an External PostgreSQL

To use an existing PostgreSQL instance instead of the bundled container:

1. Set `DATABASE_URL` in `.env` to your external connection string
2. Run only the app service: `docker compose up -d trust-portal`
3. Migrations will run automatically against the external database

### Backups

The PostgreSQL data is stored in a Docker named volume (`pgdata`). To back up:

```bash
docker exec trust-portal-db pg_dump -U trust_portal trust_portal > backup_$(date +%Y%m%d).sql
```

To restore:

```bash
cat backup_20260313.sql | docker exec -i trust-portal-db psql -U trust_portal trust_portal
```

## License

MIT License — see [LICENSE](LICENSE) for details.
