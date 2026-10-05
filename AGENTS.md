## 🚨 GIT CREDENTIALS — DO NOT TOUCH 🚨

**NEVER UNDER ANY CIRCUMSTANCES CHANGE THE CREDENTIALS USED TO WORK WITH GIT REPOS ON ANY PLATFORM (LOCAL OR REMOTE). NEVER USE THE AWS CLI CREDENTIAL HELPER FOR ANY PURPOSE WHATSOEVER.**

This includes (non-exhaustive): do not run `git config credential.helper`, `git credential-osxkeychain erase`, `git credential reject`, `aws codecommit credential-helper`, or any equivalent on any other credential store. Do not modify, delete, or rotate IAM HTTPS Git credentials, SSH keys, or stored keychain / credential-manager entries. If git authentication is failing, stop and ask the user — do not attempt to repair credentials yourself.

Rationale: the user manages their own git credentials via GitHub Desktop and a credential store shared across many concurrent workstreams (local agents, remote agents, IDEs, CLI). Any agent-side credential change cascades destructively across all of those.

---

# CLAUDE.md — AI Agent-First Trust Portal

This file provides guidance to AI coding agents when working with code in this repository.

## Overview

**ai-agent-first-trust-portal** is an open-source, white-label SOC 2 trust portal and compliance management system driven by AI agents through its REST API. One Docker image serves the public trust pages, the admin UI and the API, and runs the background jobs; PostgreSQL is its only runtime dependency. `deploy/aws/` runs it on AWS (see `deploy/README.md`); `docker-compose.yml` runs it on any single server. `README.md` is the adopter guide and holds the configuration reference.

## Product principles

- **Open source and highly opinionated.** The portal makes the compliance-tooling decisions for its adopters and builds them in.
- **Minimal configuration.** An organisation that runs on AWS, git and AI agent tools (Claude Code, Codex) adopts the portal with minimal configuration.
- **Strong defaults.** A configuration knob exists only when the portal cannot work without it; every other behaviour is a fixed, documented default.
- **Three homes for configuration.** Deployment values come from one secret (Secrets Manager, or the environment); operational configuration (git sources, collectors, team members, branding) lives in the database, edited through the admin UI or the API; policies and governance documents live in the organisation's governance repository.

Changes to the code keep to these principles: a new environment variable, setting or option needs a reason the portal cannot work without it.

## Tech Stack

- **Backend:** Python 3.12, Flask 3.1, gunicorn (gthread workers)
- **Database:** PostgreSQL 17 via SQLAlchemy 2 and Alembic
- **Frontend:** Flask/Jinja2 templates; markdown rendered with Markdown and sanitised with nh3
- **API docs:** Flasgger (OpenAPI 3.0); Swagger UI at `/api/docs/`, raw spec at `/api/openapi.json`
- **Background jobs:** APScheduler inside the gunicorn workers, one leader per database
- **Integrations:** boto3 (AWS runtime role, Secrets Manager, CloudWatch Logs, CodeCommit, collectors), requests (GitHub, platform checks), cryptography (Fernet for stored credentials)
- **Images:** `public.ecr.aws/docker/library/python:3.12-slim` and `public.ecr.aws/docker/library/postgres:17`

## Development

```bash
cp .env.example .env
docker compose -f docker-compose.dev.yml up --build
```

- The `trust-portal-dev` container builds the Dockerfile `test` target, mounts the repository at `/app`, sets `PORTAL_ENV=development`, runs `python -m cli db-migrate` and then `gunicorn -c gunicorn.conf.py --reload app.wsgi:app` on port **5100**. PostgreSQL (`trust-portal-db`) is published on host port 5433.
- `COMPLIANCE_DATA_DIR` (in `.env`) names an evidence-repository checkout, mounted read-only at `/data`, for a `local` git source or `python -m cli import --data-dir /data`.
- First admin: `docker exec trust-portal-dev python -m cli create-admin --name "<name>" --email <email> --key-file /tmp/admin.key` writes the API key only to that new file (mode 0600, never inside a git working tree; read it, then delete it); CLI logs go to stderr and no command prints a key; sign in at `http://localhost:5100/admin/login`.

## Project Structure

```
app/
  __init__.py            App factory: configuration, blueprints, security, Swagger
  runtime_config.py      Environment variables, the Secrets Manager secret, database URLs
  config.py              Fixed Flask defaults (request/form limits, cookies, CSRF, rate limits)
  request_limits.py      Request body, form and JSON limits (ROUTE_BODY_LIMITS raises per route)
  auth.py                API-key and session authentication, role decorators
  security.py            ProxyFix, security headers, CSRF, safe redirects, sanitised markdown
  audit_middleware.py    Attributes audited writes to the authenticated team member
  logging_config.py      JSON logs in production, optional CloudWatch Logs shipping
  wsgi.py                gunicorn entry point
  models/                SQLAlchemy models
  routes/                portal (public), setup, admin, admin_git, admin_store, api, crud, collectors_api,
                         git_sources_api, evidence_store_api
  services/              Business logic, including:
    git_sources/         providers.py (CodeCommit, GitHub, local), mappings.py, service.py, sync.py
    evidence_store/      The write-once S3 evidence store: keys.py, store.py (every S3 call), plans.py
                         (content checks and import plans), sync.py, verify.py, service.py
    evidence_import.py   Diff-only import engine (datasets; decision logs via evidence_import_decision_logs.py)
    scheduler.py         Leader election, cron schedules, queued-run dispatch, reaper
    audit_chain.py       Audit hash-chain verification, anchors, read-side redaction
    audit_archive.py     Archive manifests: cutover upload, anchor from a manifest, anchor verification
    audit_archive_dump.py  Verify what an archive dump contains (pg_dump custom format, streamed)
    governance_docs.py   Policy and governance documents from the governance source
    chunked_files.py     Chunked-file convention for files over 5 MiB
  templates/, static/    Jinja2 templates, CSS and JS
cli/                     `python -m cli <command>`: import, init, export, create-admin, audit-verify,
                         audit-archive-manifest, audit-anchor, run-jobs, git-source, evidence-store, scaffold,
                         db-wait, db-migrate
  loaders/, schemas/     Dataset loaders and the JSON Schemas of the evidence datasets
collectors/              Evidence collectors (aws/, git/, platform, policy, vendor) and registry.py
migrations/              Alembic environment and revisions 001-021
deploy/                  AWS deployment: CloudFormation template, scripts, Lambdas and their tests
iam/                     trust-portal-collector-policy.json, the read-only collector policy
docs/                    evidence-repo-spec.md (evidence repository format), adr/
policy-templates/        SOC 2 policy templates that `cli scaffold` copies into a governance repository
templates/governance/    CLAUDE.md / AGENTS.md templates, setup guide, independent-review prompt
templates/agent-onboarding/  Claude Code SessionStart auto-pull template
scripts/session-end-hook.sh  Claude Code SessionEnd hook that uploads session transcripts
migration/trustcloud/    Scripts that export controls, tests, evidence and policies from TrustCloud
tests/                   Unit tests (pytest)
Dockerfile               base, test and production stages
entrypoint.sh            db-wait, db-migrate, then exec the command (gunicorn)
gunicorn.conf.py         Workers, timeouts, proxy trust, scheduler start in each worker
docker-compose.yml       Single-server production stack
docker-compose.dev.yml   Development stack
docker-compose.test.yml  Isolated unit-test stack
```

## Key Conventions

- **Configuration:** the environment variables are exactly those in README.md → "Configuration reference", read through `app/runtime_config.py`. Secret-capable variables may come from the JSON secret named by `PORTAL_SECRET_ID`; a real environment variable wins. Git sources, collectors, team members and branding are configured in the database (admin UI or API), never in environment variables.
- **White-label:** no organisation-specific names, domains, account ids or resource names in code, templates, tests or documentation. `PORTAL_COMPANY_NAME`, `PORTAL_BRAND_NAME` and `PORTAL_CONTACT_EMAIL` are the branding defaults until an admin sets them in Admin → Portal Settings.
- **Policies:** `policy-templates/` holds templates that `python -m cli scaffold` copies into a governance repository. The portal renders a policy only from the version synced from the governance git source (`Policy.file_path` resolved against synced policy files), never from local disk.
- **Evidence data:** the evidence repository (`docs/evidence-repo-spec.md`) is pulled through a git source and imported diff-only; every compliance-table write produces an audit row, so the import writes only real differences. A source's default mappings (`DEFAULT_EVIDENCE_MAPPINGS`) read every kind of the layout, the evidence index, pentest evidence and decision logs included; `python -m cli import` reads the six authored datasets, and those three kinds when named (`--dataset evidence|pentest-findings`, `--decision-logs`). The evidence store imports pentest evidence and decision logs alongside every git source, adding to what the sources import; a source whose repository leaves those kinds to the store has the authored datasets' mappings (`AUTHORED_EVIDENCE_MAPPINGS`) as its `path_mappings`. The database and API are the system of record (`docs/adr/001-db-as-system-of-record.md`).
- **Evidence store:** machine-produced evidence (decision logs, AI code reviews, security-assessment output and reports, evidence artifacts) lives in a write-once S3 bucket with versioning and Object Lock (`docs/evidence-repo-spec.md` → "Evidence store"), named by `EVIDENCE_STORE_BUCKET` (unset: disabled, "not configured"). `app/services/evidence_store/` reads it through the runtime role and never writes to it; its S3 calls are only `list_object_versions`, `head_object`, `get_object`, `get_bucket_versioning`, `get_object_lock_configuration`, `get_bucket_policy` and `get_bucket_lifecycle_configuration`, all in that package (the deployment grants exactly their IAM actions). A sync (hourly periodic task on the scheduler leader, **Sync now**, `POST /api/evidence-store/sync`, `python -m cli evidence-store sync`) records the bucket's default retention on its run (written once; the bucket's first sync sets its audited retention floor, `evidence_store_retention_floors`, from it), then the first version of each key in the audited `evidence_store_objects` (key, percent-encoded with `key_escaped` when it holds a control character, version id, SHA-256, the stored composite checksum of a multipart upload, size, ETag, Object Lock state, kind, status, recording run; a version needs a SHA-256 checksum, full-object or composite - `store.stored_checksum` -, else it is `non_conforming`) and imports it by kind: decision logs through the decision-log import with the `store` authority (create a session or extend it as an exact prefix extension; an identical or prefix export is `unchanged`, an identical export of a restored session without versions baselines it as `ingested`; anything else is a conflict - `rejected` with detail `conflict: ...`, kept as a rejected version, never replacing, truncating or superseding entries; `store_object_id` on the versions; a sidecar read at its first version), pentest evidence only in the store's own namespace (never changing another source's findings; a file another source holds identically is `duplicate`, re-evaluated each sync against that source's findings' content; the record holds the findings' count and identity, compared by content; the store only inserts, each finding id derived from the object's version id, and never takes over a row; store-namespace findings are immutable: API 409 and migration 021's guard on `pentest_findings`; the API assigns every pentest finding id, a POST naming one answers 400), evidence documents as team-only `evidence_documents` linked to controls and tests by admins. Keys follow strict patterns (`keys.py`); JSON is parsed depth- and size-limited; every import first runs a pure, total content check (`plans.py`) that refuses from the body alone everything the database could refuse (NUL characters and unpaired surrogates anywhere, non-finite numbers, out-of-range date-times, wrong types; `rejected` once) and then a plan against the database (a conflict is `rejected`), and verification re-derives with the same functions and inputs; any failure after the check (S3, network, any database error) is `error`, read again by every sync, `pending` in verification and never a refusal; run details carry error classes and codes only; a prefix whose listing fails is a run error (`partial`). Later versions of a key and delete markers are anomalies. Migration 021's guards keep the records evidence for every role (identity and evidence frozen, only the status changes `error`→recorded, `duplicate`→`ingested`/`unchanged`/`duplicate`/`rejected`, `non_conforming`/`rejected`/`too_large`/`error`→`acknowledged` (recording `acknowledged_from`), any→`erased`; records and sync runs dated by the database clock; a sync run's bucket and queue time frozen and its retention written once; retention floors append-only, each row dated by the database clock, the first set by the bucket's first sync and later ones by an admin with a reason; no DELETE or TRUNCATE). `python -m cli audit-verify --evidence-store [--full]` checks the bucket (versioning, default retention no lower than the retention floor, bucket-policy denials on every store prefix with strictly parsed statements and resources in the portal's region's partition, other statements never failing it, no expiring lifecycle rule, a first floor equal to the default the first sync observed and no lower than the earliest recorded version's retention, every floor lowering listed; an erasure principal makes it `unverified`, one holding `*`, `?` or `$` fails), every record against its own bucket (including retention from the upload time `HeadObject` reports against the floor) and against its import outcome with the store as ground truth (every outcome that is not a straightforward import - unchanged, duplicate, rejected, too_large - re-derived from the version's body on every run by the worker pool with the sync's own check and plan, refusals listed; an ingested pentest file's findings recomputed from their content; `--full` also re-reads every body), the store-namespace findings (any no store object imported fails), the evidence documents, the store conflicts (informational) and the listing - the API in slices of at most `max_items` records and 256 MiB of bodies (`budget_exhausted`, continued with `next_cursor`), the CLI unbounded with bounded memory; `--decision-logs --against-store` re-reads and parses every store-imported transcript version's object; `evidence-store record-erasure` (the version must be absent) records a documented erasure, `evidence-store acknowledge` (one version or `--file` of JSON lines) a non-conforming upload, a refusal that no longer re-derives or an error that failed at least 3 syncs and `evidence-store set-retention-floor` the floor (the only way to lower it); all three take `--bucket` for a former bucket, and their `--admin` is asserted by the operator shell that holds the database credentials. Documents are served spooled, at most two reads at once per process (else 429).
- **Collectors:** configured in the database (`/admin/collectors`, `/api/collectors/*`), with stored credentials Fernet-encrypted by `COLLECTOR_ENCRYPTION_KEYS`. The app starts and runs with no collector and no git source configured.
- **Background work:** the scheduler starts in each gunicorn worker (`post_worker_init`) and exactly one process per database holds the leader lock. Job kinds (collector runs, git syncs, evidence-store syncs) each have their own advisory lock class (8150, 8151, 8152) and at most one queued or running run per target. The app factory, migrations, the CLI and tests never start it; `python -m cli run-jobs` executes queued runs in the calling process.
- **Decision logs:** session transcripts arrive through `POST /api/decision-log/upload`, the evidence repository's `decision-logs/` (git sync), the evidence store's `decision-logs/` (store sync) or the local `decision-logs/` ingest. `app/services/transcript_ingest.py` parses Claude Code JSONL (also written by openclaude) and Codex rollout JSONL, detecting the format from the records, and labels each new session's `agent_type` with the uploader's `agent` (upload parameter or `.meta.json` sidecar field) or, without one, the detected format's agent.
- **Evidence files** uploaded through the API or admin UI are stored in the database. `evidence-artifacts/` and `decision-logs/` are gitignored local staging directories.
- **Port 5100** for the trust portal.

## Authentication

- **API keys:** one per team member, sent as `X-API-Key: <key>` or `Authorization: Bearer <key>`. Keys are stored as SHA-256 digests and shown once, at creation or regeneration (`python -m cli regenerate-key`, or Team Members). Migration `017` revoked every key issued before it; a member with no key (`key_rotation_required`) is re-keyed by an admin.
- **Browser sessions:** a member signs in once with the key (`/admin/login`, or `/admin/client-login` for clients); the signed session cookie holds only the member id, a fingerprint of the current key and the sign-in time, so regenerating the key or deactivating the member ends every session, and every session ends `SESSION_ABSOLUTE_LIFETIME` (12 hours) after sign-in. When an API-key header is present, only that key authenticates the request.
- **Roles:** `human` and `agent` members read and write compliance data; `client` members (external reviewers, with an optional expiry) are read-only and limited to the data of the client report. `is_compliance_admin` members use `/admin/*` (including team management) and the admin-only API routes (settings updates, collectors, git sources, evidence-store sync and verification, document links). Evidence documents are team-only (`require_team`): never served to client keys, anonymous requests or public pages.
- **Public routes:** the trust pages (`/`, `/controls`, `/policies`, `/systems`, `/vendors`, `/risks`, `/status`, `/legal`, `/ai-transparency`), `/api/health`, `/api/docs/`, and `/setup` / `POST /api/setup` while no admin exists.
- **CSRF:** unsafe requests (POST, PUT, PATCH, DELETE) authenticated by the session cookie carry the session's CSRF token (`csrf_token` form field or `X-CSRF-Token` header); a request is exempt only when its API-key header authenticates. Public pages set no cookie.
- **Session revocation:** logout increments `team_members.session_epoch`; a session of an earlier epoch is rejected. The portal always keeps a durable admin (usable key, no expiry or one more than 30 days away): deactivation is refused unless another remains (`team_service.LastAdminError`).
- **Rate limits** are one atomic upsert per attempt on `auth_rate_limit` (`rate_limit.consume`), shared by every process.
- **Public sections:** `portal_settings.public_sections` (default: every section but `risks`) decides which public pages exist; a new public page is registered in `settings_service.PUBLIC_SECTIONS` and decorated with `@public_section(<key>)`. Control names appear elsewhere only while `controls` is published.
- **Outbound HTTP** from collectors and git providers goes through `app/services/safe_http.py` (no private, loopback, link-local or metadata addresses; every redirect and the connected peer re-checked), never through a proxy (`trust_env=False`).
- **Client allowlist:** client keys are default-deny on `/api/*`; `CLIENT_ALLOWED_ENDPOINTS` in `app/auth.py` lists the GET routes the client report needs (approved policies only). A new route stays hidden from clients unless it is added there.
- **Rate limits:** failed logins, client logins and `/setup` attempts are limited per client IP (10 per 15 minutes) through the `auth_rate_limit` table, shared by every process. Client members start at most AUTH_RATE_LIMIT_ATTEMPTS sessions per window, per member (`auth.consume_client_session`).
- **Request limits:** a route needing more than 1 MiB is listed in `app/request_limits.ROUTE_BODY_LIMITS`.
- **Bootstrap:** while no active compliance admin holds an API key and `BOOTSTRAP_TOKEN` (at least 32 characters in production) is set, `/setup` (form) and `POST /api/setup` (`Authorization: Bearer <token>`, body `{"name", "email"}`) create an admin. While an active admin holds a key both return 404.

## Audit Log

- Triggers on every compliance, team, settings, collector, decision-log session and version, git-source and evidence-store table append one `audit_log` row per change, attributed through the `app.current_team_member` transaction setting. `decision_log_entries` is not audited per row: each stored transcript version is an audited `decision_log_transcripts` row with `entry_count` and `entries_sha256`, and imports write entries before the audited rows (the deferrable FK `fk_decision_log_entries_session`). Versions are history: migration 018's guard lets a current version become superseded (identity, counts and digests unchanged; content and reason required), freezes superseded versions entirely and refuses every other UPDATE, DELETE and TRUNCATE for every role. Store imports (`store_object_id` set) use the `store` authority: they create a session, extend it as an exact prefix extension or baseline a restored session they hold identically, and never win a conflict (a differing export is rejected, kept for review); the guard (as of migration 021) also freezes `store_object_id` and applies the path rule to store imports. `--decision-logs` fails a store-linked version whose object is not recorded `ingested` (or `erased`) and a `repository conflict:` step whose successor is a store import. Once the evidence repository or the evidence store has supplied entries of a session, only they may extend it (other uploads: 409, kept as rejected versions); entries after theirs are unconfirmed and never count as verifications. `python -m cli audit-verify --decision-logs` checks that each session's history only grows (superseded versions are prefixes of the current entries except across a `repository conflict:` replacement whose successor is a repository import recorded, with the session's conflict, in one audited transaction; counts never decrease) and that every version still has the digest, count and content the audit log recorded (`app/services/decision_log_verify.py`). `--against-repo` fetches every repository-import version from the evidence git source at its recorded `source_commit` and compares SHA-256, entry count and entries digest (`app/services/decision_log_repo_verify.py`): the repository is ground truth for imports. A version's path must be its own session's file (verified, and refused at write time by the importer and the 018 guard for commit-bearing imports); a commit-less import on a CodeCommit/GitHub source is broken, and a SOC 2 evidence run requires `unverified` = 0. A full re-import baselines restored sessions the repository holds identically (a repository-import version, no entry rows) and treats differing ones as conflicts; sessions with no repository import are listed as `not_in_repository` (sessions the evidence store holds as `in_store`). `--against-repo` never counts store-import versions and, without any evidence git source, still runs (a commit-bearing import is then `no_source`, unverifiable); `--against-store` checks every store-import version against its recorded and stored object, re-reading the object's body and comparing its SHA-256, entry count and entries digest (`app/services/evidence_store/verify.py`).
- **Hash chain (`hash_version` 2):** `row_hash = sha256(previous_hash || table_name || record_id || action || changed_by || changed_at || old_values || new_values)`; the first row links to 64 zeros or to an ANCHOR row. A statement-level `audit_chain_lock()` trigger takes the chain's transaction-scoped advisory lock before any row lock, serialising appends without deadlocks.
- **Trigger functions** are SECURITY DEFINER with `search_path = pg_catalog, pg_temp`: every table is `public.`-qualified and every concatenation uses `OPERATOR(pg_catalog.||)` on explicit `::text` operands, so no object in any other schema can be resolved by them. They refuse tables outside `public` and are executable only by the owner; the application role has no TEMPORARY or CREATE privilege.
- **Lock order:** writers take the chain's advisory lock before any row lock (statement-level `audit_chain_lock()` on every audited table and on the link tables `policy_controls` and `vendor_systems`). Code that row-locks audited rows another way (`SELECT ... FOR UPDATE`) calls `audit_chain.lock_audit_chain(session)` first. Migrations lock only what their pending revisions need (`REVISION_LOCKS` in `migrations/env.py`: ACCESS EXCLUSIVE on the existing tables they alter, in writer order with `audit_log` last and only when altered, then the chain lock only when a revision writes audited rows), requesting every lock without waiting, within a bounded, retried budget.
- **Digested columns:** API key digests, stored credentials (`collector_config`, `git_sources`), `evidence.file_data`, `decision_log_transcripts.content_gz`, `collector_run.raw_log`, `collector_check_result.detail`, `pentest_findings.other_data`, `git_file_versions.content` and `evidence_store_sync_runs.details` are recorded as `sha256:<hex>` only (of the raw bytes for a bytea column, whatever `bytea_output`). A new bulky or binary column of an audited table is added to its trigger's digested columns. An UPDATE that changes only `updated_at` records nothing.
- **Append-only:** a trigger rejects UPDATE, DELETE and TRUNCATE on `audit_log` for every role, and the application role holds SELECT only on `audit_log`, and no DELETE on `evidence_store_objects`, `evidence_documents`, `evidence_store_sync_runs` and `evidence_store_retention_floors` (`NO_DELETE_TABLES` in `cli/db_cmd.py`; migration 021's guards also refuse it for every role). In production the web process refuses to serve as a role that owns the audited tables or may write `audit_log` (`app/serving.py`, `python -m cli db-check-role`); owner credentials (`DATABASE_OWNER_*`) exist only in the environment of the migration step.
- **Witness:** with `AUDIT_WITNESS_BUCKET` set and the witness ARMED (owner-only, audited: `python -m cli audit-witness-arm`, or `audit-anchor --manifest` at cutover; table `audit_witness_arming`, migration 020), the chain head is published to `chain-heads/` in an S3 Object Lock bucket (`app/services/audit_witness.py`) with `If-None-Match: *` (a different object at the key is a logged conflict; the head goes out under the next second's key): at leadership start, hourly when changed, and after arming or anchoring. An unarmed database never publishes. `AUDIT_WITNESS_DISABLED=true` (environment only) overrides everything. `/api/health` reports `witness` (`disabled`, `unconfigured`, `unarmed`, `enabled`), `last_published_at` and `witness_stale` (enabled, head moved, nothing published for over two hours; also logged as `audit_witness_stale` and shown on the admin dashboard). Verification reads every object version under `chain-heads/`; the object KEY is authoritative: a body that disagrees with its key, an object over 4 KiB, non-JSON, schema-invalid or unreadable is an invalid witness object (reported with its key; status `broken`). A missing or different row of the current chain, a published chain that no VERIFIED archive manifest of the anchor lineage names with that chain's last published head as its final row, or heads with none of the current chain are witness mismatches.
- **Anchor:** a restored database continues an archived chain from an ANCHOR row that names an archive manifest in the witness bucket: `python -m cli audit-archive-manifest` (operator credentials, old database) uploads the dump, publishes the final head and writes `archives/<chain id>/<name>.manifest.json`; `python -m cli audit-anchor --manifest <key>` (owner role) anchors only to a manifest that verifies. `python -m cli audit-verify-archive --dump <file> --scratch-url <db>` checks what the archive contains (its chain, every published head of it, and the manifest's SHA-256, size, final row and count). Verification accepts an anchor only when its manifest (at `archives/<chain id>/<name>.manifest.json`), the archive object and the archived chain's published final head all match it, and the manifest's own `source_anchor` verifies the same way (`app/services/audit_archive.py`); without witness access it is `unverified`, never `valid`. There is no HTTP anchor route.
- **Verify:** `python -m cli audit-verify [--witness-s3 | --witness-file]` (unbounded) or `GET`/`POST /api/audit-log/verify` (admins; 250,000 rows and 10,000 heads per request) recomputes every hash inside PostgreSQL, resumable with `after_id` and `expected_previous_hash`, and reports content mismatches, forks (content intact, links to an earlier row than the predecessor, only before the first serialised row), true breaks, witness mismatches and invalid witness objects separately (lists truncated to 100 with counts); status `valid`, `intact_with_forks`, `unverified` or `broken`.

## API Documentation

Every API route carries an OpenAPI 3.0 docstring (Flasgger); a new route carries one too. Interactive docs are served at `/api/docs/` and the raw spec at `/api/openapi.json`.

## Database Migrations

- 21 revisions, `001` to `021`, in `migrations/versions/`, forward-only.
- Applied at container start, never at app startup: the production entrypoint runs `python -m cli db-wait` and `python -m cli db-migrate`, then removes `DATABASE_OWNER_*` from the environment before starting gunicorn; the development compose command runs `python -m cli db-migrate`. `db-migrate` runs `alembic upgrade head` as the owner role when `DATABASE_OWNER_*` / `DATABASE_OWNER_URL` is set and then provisions the application role's grants. When the database is at a revision the code does not know (a newer release migrated it), it skips the upgrade with a warning.
- **Revision checks:** `db-migrate` skips the upgrade (and the role provisioning) when the database is at a well-formed revision id after the image's head; any other unknown revision is an error (exit 1, health 503).
- **Expand/contract:** a release's revisions only add (tables, columns, functions, triggers) and keep what the previous release reads, so the previous image runs against the new schema; removals (the contract step, e.g. dropping `team_members.api_key`) ship in a later release. Rolling back across a contract step is a snapshot restore.
- A new revision gets a `REVISION_LOCKS` entry: every existing table it locks beyond ACCESS SHARE (altered, written, or referenced by a new foreign key or index) and whether it writes audited rows; without one it locks every table and the audit chain.
- A revision is fast on a large `audit_log` (metadata-only DDL). A new audited table gets both triggers through `audit_table_sql(<table>, <digested columns>)` from `016_audit_log_v2.py`, the way `019_git_sources.py` does.
- New revision:

```bash
docker exec trust-portal-dev alembic revision --autogenerate --rev-id 022 -m "Describe the change"
```

Review the generated operations before committing them.

## Testing

**Docker-only testing — no venv:** All tests run inside Docker. Do NOT create or use Python virtual environments (`venv`, `virtualenv`, `pipenv`, `conda`, etc.). Dependencies are managed inside the Docker image.

Full suite (PostgreSQL-backed tests included), with a unique project name:

```bash
docker compose -p tp-test-$$ -f docker-compose.test.yml run --rm tests
docker compose -p tp-test-$$ -f docker-compose.test.yml down -v
```

The `tests` service builds the Dockerfile `test` target and sets `TEST_DATABASE_URL` to its own PostgreSQL 17 on tmpfs; the exit code is pytest's. `pytest.ini` collects `tests` and `deploy/aws/tests`, and the image runs them with coverage of `app`, `cli` and `collectors`.

Inside the running dev container, `docker exec trust-portal-dev pytest` runs the SQLite-backed tests; the PostgreSQL-backed tests (audit triggers, advisory locks, migrations) are skipped there because `TEST_DATABASE_URL` is unset.

Target: >= 80% coverage. Mock AWS with `moto` and GitHub with `unittest.mock`; tests make no network calls.

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
