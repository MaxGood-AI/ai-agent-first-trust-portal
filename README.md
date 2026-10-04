# AI Agent-First Trust Portal

### Let AI agents get you to SOC 2 Type 2 compliance

The AI Agent-First Trust Portal is an open-source SOC 2 trust portal and compliance management system that your AI agents operate through a REST API. It publishes a public trust page; keeps controls, tests, evidence, systems, vendors and risks in PostgreSQL behind a tamper-evident audit log; pulls policies from your governance repository and compliance data from your evidence repository; runs evidence collectors against AWS and your git host; and records every AI agent session as a decision log. It is deliberately opinionated: an organisation on AWS, git and Claude Code or Codex adopts it with one CloudFormation stack, two git repositories and a handful of commands.

## Features

### Agent-first compliance
- **Full REST API** — every compliance operation (record test results, submit evidence, upload files, verify the audit log) with per-member API keys
- **Batch operations** — record results and submit evidence for many tests in one call
- **Decision log** — AI agent session transcripts (Claude Code, openclaude, OpenAI Codex) uploaded at session end, each session labelled with the agent that wrote it, with "done." verification acknowledgments detected automatically
- **Tamper-evident audit log** — SHA-256 hash chain over every compliance change, append-only, with a verification endpoint
- **Agent skill** — the companion [trust-portal skill](https://github.com/MaxGood-AI/ai-agent-first-trust-portal-skill) gives agents commands for every API operation

### Compliance management
- **Controls, tests and evidence** — SOC 2 controls and tests with pass/fail execution history and evidence files stored in the database
- **Git-pulled governance and evidence** — policies and governance documents versioned from your governance repository; compliance datasets imported from your evidence repository, reading and writing only what changed
- **Evidence collectors** — AWS (IAM, RDS, S3, CloudTrail), CodeCommit change management, platform health, policy currency and vendor inventory, configured and scheduled in the admin UI
- **Policy templates** — ten SOC 2 policies ready to customise
- **Governance templates** — CLAUDE.md and AGENTS.md templates that make AI agent work part of the SOC 2 evidence chain

### Trust portal
- **Public pages** — overview, controls, policies, systems, vendors, risks, status and AI transparency statement
- **Admin UI** — evidence gaps, collectors, git sources, governance documents and change history, team, audit log, settings
- **Interactive API documentation** — Swagger UI at `/api/docs/`
- **White-label** — branding set in the admin UI
- **Production deployment on AWS** — one CloudFormation stack ([deploy/README.md](deploy/README.md)); `docker-compose.yml` for any single server

## Adopt in 30 minutes

### 1. Prerequisites

- An AWS account, with the AWS CLI v2, `jq` and `curl` signed in to it.
- A git host for two private repositories: AWS CodeCommit or GitHub.
- Claude Code or Codex on the workstations of the people who run the compliance program.
- Docker, to run the portal's CLI and to try the portal locally.

### 2. Create the governance and evidence repositories

Scaffold both repositories with the portal's CLI, run from the portal's `test` image:

```bash
git clone https://github.com/MaxGood-AI/ai-agent-first-trust-portal.git
cd ai-agent-first-trust-portal
docker build --target test -t trust-portal:test .
mkdir -p ~/compliance
docker run --rm --user "$(id -u):$(id -g)" -v ~/compliance:/out trust-portal:test \
  python -m cli scaffold --governance-dir /out/governance --evidence-dir /out/evidence \
  --company "Example Corp Inc."
```

- `~/compliance/governance` holds `policies/*.md` (the ten policy templates), `CLAUDE.md` and `AGENTS.md` (from `templates/governance/`), `README.md`, `infrastructure/` and `agent-config/`.
- `~/compliance/evidence` holds the layout of [docs/evidence-repo-spec.md](docs/evidence-repo-spec.md): empty datasets, a `policy-index.json` entry for every policy (status `draft`), `evidence/`, `pentest-evidence/layer1/` to `layer4/`, and `decision-logs/`.

Create two empty repositories on your git host (CodeCommit: `aws codecommit create-repository --region <region> --repository-name <repository-name>`), then push each directory:

```bash
cd ~/compliance/governance
git init -b main
git add .
git commit -m "Create governance repository"
git remote add origin <governance repository clone URL>
git push -u origin main
```

Repeat for `~/compliance/evidence`. Rewrite every section marked `CUSTOMIZE` in each policy to describe what your organisation actually does; a policy appears on the public trust page once its `status` in `policy-index.json` is `approved`.

### 3. Deploy the stack

Follow the [Runbook in deploy/README.md](deploy/README.md#runbook): deploy the CloudFormation stack, build the first image and deploy it. With CodeCommit, set the stack parameters `GovernanceRepository` and `EvidenceRepository` to the two repository names so the portal's runtime role can read them. The stack generates the runtime secret, including `SECRET_KEY`, the database passwords, `BOOTSTRAP_TOKEN` and `COLLECTOR_ENCRYPTION_KEYS`.

### 4. Point your domain at the portal

Set the stack parameter `DomainName` (and `HostedZoneId` when the domain is in Route 53), then follow the runbook's *Validate the certificate* step in [deploy/README.md](deploy/README.md#runbook): `deploy/aws/certificate-dns.sh` writes the validation records to Route 53 or prints them for your DNS provider, and once the certificate is `ISSUED` a stack update with `AttachCustomDomain=true` attaches the domain. With `HostedZoneId` the stack also creates the CNAME to the container service; with another DNS provider, create that CNAME yourself, pointing at the host of the `ContainerServiceUrl` stack output.

### 5. Create the first admin

Read the bootstrap token from the runtime secret:

```bash
aws cloudformation describe-stacks --region <region> --stack-name <stack> \
  --query "Stacks[0].Outputs[?OutputKey=='PortalSecretArn'].OutputValue" --output text
aws secretsmanager get-secret-value --region <region> --secret-id <PortalSecretArn> \
  --query SecretString --output text | jq -r .BOOTSTRAP_TOKEN
```

Open `https://<your-domain>/setup` and enter the token, your name and your email. The page shows the new admin's API key once. The same from a shell:

```bash
curl -sS -X POST https://<your-domain>/api/setup \
  -H "Authorization: Bearer <BOOTSTRAP_TOKEN>" -H "Content-Type: application/json" \
  --data '{"name": "<full name>", "email": "<email>"}'
```

It answers `201 {"member_id": "...", "api_key": "..."}`. While an active admin holds an API key, `/setup` and `/api/setup` answer 404; they accept the token again only when no active admin holds one. Keep the key in a password manager and sign in at `https://<your-domain>/admin/login`.

#### Moving an existing portal database (mandatory key rotation)

Migration `017` revokes every API key issued before it: earlier releases recorded keys in plaintext in audit rows that are append-only and cannot be cleaned, so none of those keys may be trusted. Members keep their identities and history; each needs a new key. After restoring or upgrading such a database:

1. Create an admin through `/setup` with the bootstrap token (it is open again because no admin holds a key), or run `python -m cli regenerate-key --member <admin id or email> --key-file <new file>` where you have a shell.
2. In **Team Members**, regenerate the key of every member marked "No key", and hand each new key to its owner (agents: update their `TRUST_PORTAL_API_KEY`).

### 6. Connect the repositories

In the admin UI open **Git Sources**, add a source with role `governance` and one with role `evidence`, and press **Sync now**. The same through the API, for CodeCommit (read through the portal's runtime role):

```bash
curl -sS -X POST https://<your-domain>/api/git-sources \
  -H "X-API-Key: <admin API key>" -H "Content-Type: application/json" \
  --data '{"name": "governance", "role": "governance", "provider": "codecommit", "repository": "<governance-repository>", "branch": "main", "credential_mode": "runtime_role", "schedule_cron": "*/30 * * * *"}'
```

and for GitHub (`portal_secret` reads `GITHUB_TOKEN` from the runtime secret; set it with `deploy/aws/set-secret-key.sh` and redeploy, as in deploy/README.md → Operations; the token needs read access to the contents of both repositories):

```bash
curl -sS -X POST https://<your-domain>/api/git-sources \
  -H "X-API-Key: <admin API key>" -H "Content-Type: application/json" \
  --data '{"name": "evidence", "role": "evidence", "provider": "github", "repository": "<owner>/<evidence-repository>", "branch": "main", "credential_mode": "portal_secret", "schedule_cron": "*/30 * * * *"}'
```

Start a sync and follow it:

```bash
curl -sS -X POST -H "X-API-Key: <admin API key>" https://<your-domain>/api/git-sources/governance/sync
curl -sS -H "X-API-Key: <admin API key>" https://<your-domain>/api/git-sources/governance/runs/<run id>
```

The first call answers `202` with the run's `id` and `poll_url`; the run is finished when its `status` is `success`, `partial`, `failure` or `unchanged`. With `schedule_cron` set, the portal syncs on that schedule from then on.

### 7. Connect your agents

1. **API keys.** In the admin UI open **Team Members** and create one member per person and per agent (role `human` or `agent`; `client` for read-only external reviewers). Each key is shown once.
2. **Agent skill.** Install [ai-agent-first-trust-portal-skill](https://github.com/MaxGood-AI/ai-agent-first-trust-portal-skill) as its README describes, with `TRUST_PORTAL_API_URL=https://<your-domain>` and `TRUST_PORTAL_API_KEY=<member key>` in the workspace `.env`.
3. **Decision logs (Claude Code).** Copy `scripts/session-end-hook.sh` to each workstation (for example into the governance repository's `scripts/`), make it executable, and register it as a `SessionEnd` hook in Claude Code's `settings.json`:

   ```json
   {
     "hooks": {
       "SessionEnd": [
         {"hooks": [{"type": "command", "command": "/absolute/path/to/session-end-hook.sh", "timeout": 60}]}
       ]
     }
   }
   ```

   The hook captures sessions whose working directory is under `TRUST_PORTAL_DEV_DIR` (default `~/Development`), reads `TRUST_PORTAL_API_URL` and `TRUST_PORTAL_API_KEY` from the environment or from `<dev dir>/.env`, and uploads the transcript to `POST /api/decision-log/upload`. It keeps a local copy in `<dev dir>/decision-logs/` (`TRUST_PORTAL_STAGING_DIR`) and stages failed uploads in its `.retry/` subdirectory.
4. **Session start (Claude Code, optional).** [templates/agent-onboarding/INSTALL.md](templates/agent-onboarding/INSTALL.md) installs a `SessionStart` hook that brings every repository of the workspace up to date before the agent's first turn.

## Try it locally

```bash
git clone https://github.com/MaxGood-AI/ai-agent-first-trust-portal.git
cd ai-agent-first-trust-portal
cp .env.example .env
docker compose -f docker-compose.dev.yml up --build
```

The portal runs at `http://localhost:5100` (API docs at `/api/docs/`) with live reload; PostgreSQL is on host port 5433. Create an admin and sign in at `http://localhost:5100/admin/login` with the printed key:

```bash
docker exec trust-portal-dev python -m cli create-admin --name "Your Name" --email you@example.com \
  --key-file /tmp/admin.key
docker cp trust-portal-dev:/tmp/admin.key ~/trust-portal-admin.key && docker exec trust-portal-dev rm /tmp/admin.key
```

To load an evidence repository, set `COMPLIANCE_DATA_DIR` in `.env` to its absolute path (for example the scaffolded `~/compliance/evidence`, written out in full), apply it with `docker compose -f docker-compose.dev.yml up -d`, and add it as a local-directory git source; the directory is mounted read-only at `/data`:

```bash
docker exec trust-portal-dev python -m cli git-source add --name evidence --role evidence --provider local --repository /data
docker exec trust-portal-dev python -m cli git-source sync --name evidence
```

The local provider reads the directory as it is on disk and has no history. `docker exec trust-portal-dev python -m cli import --data-dir /data` imports the same files once, without a git source.

## Configuration reference

The portal is configured by the environment variables below. Variables marked **Secret** may instead be keys of the JSON secret named by `PORTAL_SECRET_ID`. Precedence: a real, non-empty environment variable, then the secret, then the default.

| Variable | Required | Default | Secret | Purpose |
|---|---|---|---|---|
| `PORTAL_ENV` | no | `production` | no | `production`, `development`, or `test` (unit suite). Production refuses a missing, short or placeholder `SECRET_KEY` and sets Secure cookies and HSTS. |
| `PORTAL_SECRET_ID` | on AWS | — | no | Secrets Manager secret id or ARN holding a JSON object whose keys are variable names from this table. |
| `AWS_REGION` | on AWS | — | no | Region for STS, Secrets Manager, CloudWatch Logs and CodeCommit (`AWS_DEFAULT_REGION` is read when it is unset). |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | on AWS | — | no | Base credentials (standard boto3 chain). Their only permission is `sts:AssumeRole` on the runtime role. |
| `AWS_RUNTIME_ROLE_ARN` | on AWS | — | no | Role assumed from the base credentials for every AWS call, in a session that refreshes itself. |
| `AWS_RUNTIME_ROLE_EXTERNAL_ID` | no | — | no | External id for that AssumeRole. |
| `SECRET_KEY` | in production | — | yes | Flask session signing key, at least 32 characters. Generate with `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`. |
| `DATABASE_URL` | one of | — | yes | Full SQLAlchemy URL for the application role. |
| `DATABASE_HOST` / `DATABASE_PORT` / `DATABASE_NAME` / `DATABASE_USER` | one of | port `5432` | yes | Component form, used when `DATABASE_URL` is unset. |
| `DATABASE_PASSWORD` | with components | — | yes | Application-role password. |
| `DATABASE_SSLMODE` | no | `require` in production, `prefer` otherwise | yes | libpq `sslmode` for the component form. |
| `DATABASE_OWNER_USER` / `DATABASE_OWNER_PASSWORD` | in production | — | **no** | Migration-owner role (for example the Lightsail master user), read only from the environment of the migration step and removed before the web server starts. Migrations run as the owner; the application role `DATABASE_USER` is created when missing with its password set from `DATABASE_PASSWORD`, granted DML on every table except `audit_log` (SELECT only), and denied TEMPORARY and CREATE. When unset, one role does everything, which only development and test accept. |
| `DATABASE_OWNER_URL` | no | — | **no** | URL form of the owner role. |
| `COLLECTOR_ENCRYPTION_KEYS` | no | — | yes | Comma-separated Fernet keys, primary first, encrypting credentials stored in the database (collectors, git sources). Needed only to store such credentials. `COLLECTOR_ENCRYPTION_KEY` (one key) is read when `COLLECTOR_ENCRYPTION_KEYS` is unset. Generate with `python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`. |
| `BOOTSTRAP_TOKEN` | no | — | yes | Enables `/setup` (creating an admin) while no active admin holds an API key. At least 32 characters in production (startup is refused otherwise). |
| `GITHUB_TOKEN` | no | — | yes | Token for GitHub git sources with credential mode `portal_secret`. |
| `CLOUDWATCH_LOG_GROUP` | no | — | yes | Existing log group that also receives the application and access logs, one stream per process. Up to 16 MiB / 50,000 records wait to ship; records beyond that are dropped from shipping, still go to stdout, and are counted on stderr. |
| `AUDIT_WITNESS_BUCKET` | no | — | yes | S3 bucket with Object Lock that receives the audit chain head under `chain-heads/` and holds the archives and archive manifests under `archives/` (see "Audit log"). Unset: no publishing, and an anchored chain verifies as `unverified`. |
| `AUDIT_WITNESS_DISABLED` | no | `false` | **no** | `true` turns chain-head publishing and archive-manifest writing off whatever `AUDIT_WITNESS_BUCKET` says (also when the bucket comes from the secret). It overrides arming; production logs a warning at startup. `/api/health` reports `"witness": "disabled"`, `"unarmed"`, `"enabled"` or `"unconfigured"`. |
| `LOCAL_SOURCE_ROOTS` | no | — | no | `:`-separated directories that local-directory git sources may read (resolved, symlinks followed); a source must be one of them or inside one. A local source walks and hashes only the directories its mappings can match (and never `.git`, `node_modules` or similar), so unrelated files neither cost time nor change its head. Unset: local sources are refused in production and unrestricted in development and test. |
| `LOG_LEVEL` | no | `INFO` | no | Root log level. Logs are JSON lines on stdout in production. |
| `TRUSTED_PROXY_HOPS` | no | `1` in production, `0` otherwise | no | Number of reverse proxies whose `X-Forwarded-*` headers are trusted. |
| `WEB_CONCURRENCY` | no | `2` | no | gunicorn worker processes (4 threads each). |
| `PORTAL_COMPANY_NAME` / `PORTAL_BRAND_NAME` / `PORTAL_CONTACT_EMAIL` | no | `Your Company` / `Your Brand` / `compliance@example.com` | no | Branding defaults until an admin sets them in **Portal Settings**. |

The image also carries `PORTAL_VERSION`, set by the `PORTAL_VERSION` build argument and reported by `/api/health`. The compose files read `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `PORT` and `COMPLIANCE_DATA_DIR`, and workstations read `TRUST_PORTAL_API_URL` and `TRUST_PORTAL_API_KEY` (agent skill, SessionEnd hook); the portal itself reads none of these.

Git sources, collectors, team members and branding are configured in the database through the admin UI or the API, never through environment variables.

### The runtime secret

A JSON object whose keys are variable names from the table. Only the keys marked **Secret** are read; any other key is ignored. Each process reads the secret once at start, through the runtime role. Example:

```json
{
  "SECRET_KEY": "<64 random characters>",
  "DATABASE_PASSWORD": "<application role password>",
  "BOOTSTRAP_TOKEN": "<at least 32 random characters>",
  "COLLECTOR_ENCRYPTION_KEYS": "<Fernet key>",
  "CLOUDWATCH_LOG_GROUP": "<log group name>",
  "AUDIT_WITNESS_BUCKET": "<Object Lock bucket>"
}
```

The AWS stack generates and maintains this secret (see [deploy/README.md](deploy/README.md)). The owner role's password is kept in a separate secret that only the deploy role can read; the deployment passes it to the container's migration step as `DATABASE_OWNER_USER` / `DATABASE_OWNER_PASSWORD`. Rotating the owner password requires an immediate redeploy: the running containers keep the old value for their next migration step until they are replaced.

### Minimal AWS container environment

`AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_RUNTIME_ROLE_ARN` (plus `AWS_RUNTIME_ROLE_EXTERNAL_ID` when the role requires one), `PORTAL_SECRET_ID`, `DATABASE_OWNER_USER` and `DATABASE_OWNER_PASSWORD` (migration step only), and either the database components (`DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_NAME`, `DATABASE_USER`) or nothing else database-related (all of it in the secret).

## How it works

### Architecture

- **One image** (Dockerfile target `production`), running as the unprivileged user `portal` (uid 10001) with no writable paths, serving HTTP on port 5100. TLS terminates upstream (the Lightsail endpoint, or your reverse proxy).
- **Entrypoint:** load the configuration (environment and secret), wait for the database (up to 120 s), run `alembic upgrade head` as the owner role, provision the application role's grants, remove the owner credentials from the environment, then start gunicorn. When the database is at a revision the image does not know (a newer release migrated it), the upgrade is skipped with a warning so the previous image can be redeployed. Any failure before gunicorn exits non-zero, so a failed release never becomes healthy.
- **Application role:** `db-migrate` provisions it in one transaction, giving every object exactly the role's final privileges (nothing is granted and then revoked): CONNECT, USAGE on schema `public`, SELECT/INSERT/UPDATE/DELETE on every table and USAGE/SELECT on every sequence, but SELECT only on `audit_log`, `audit_witness_arming` and `alembic_version`; TEMPORARY and CREATE on the database, CREATE on `public`, TRUNCATE, REFERENCES, TRIGGER and MAINTAIN are revoked.
- **Serving role:** each gunicorn worker checks its database role before serving, together with every role it can use (every role it is a member of, directly or indirectly, whether the membership inherits privileges or only allows `SET ROLE`). In production it refuses to start when any of them is a superuser or has CREATEROLE, BYPASSRLS or REPLICATION; is `pg_execute_server_program` or `pg_write_server_files`; owns the database or any portal table, sequence, function or schema; holds TEMPORARY or CREATE on the database, CREATE on any schema or TRIGGER on any table; may write `audit_log` or `audit_witness_arming` (INSERT or UPDATE on any column, DELETE, TRUNCATE or MAINTAIN, directly, through PUBLIC or through a role such as `pg_write_all_data` or `pg_maintain`); or may set `session_replication_role`. The check runs with a fixed `search_path` and schema-qualified catalog references, so objects the role creates elsewhere cannot mislead it. Development and test log a warning. `python -m cli db-check-role` runs the same check.
- **Database connections** use a 10 s connect timeout, TCP keepalives (idle 30 s, interval 10 s, 3 probes) and a 30 s TCP user timeout on the client, and the same keepalives on the server side, so the server ends the session of a vanished process, releasing its locks, within about a minute; startup `options` in the database URL are kept. In the web process each statement is limited to 60 s. Scheduler lock connections also set a 500 ms `lock_timeout`.
- **gunicorn:** `gthread` workers (`WEB_CONCURRENCY` x 4 threads), 120 s request timeout, 30 s graceful shutdown, access log on stdout.
- **Scheduler:** every gunicorn worker starts a standby scheduler thread; exactly one process per database holds the leader lock (`pg_try_advisory_lock`), across workers, nodes and rolling deploys. The leader runs the cron schedules of collectors and git sources (re-read every 30 s, so edits apply without a restart), executes queued runs, reaps runs whose process died and prunes old rate-limit rows. A new leader queues one run for each schedule that fired without a run while no leader ran; schedules added while a leader runs start from the present.
- **Health:** `GET /api/health` answers `200 {"status": "ok", "service": "trust-portal", "database": "connected", "schema": "current", "version": "<PORTAL_VERSION>", "witness": "enabled", "last_published_at": "2026-10-01T05:00:00Z", "witness_stale": false}` (`witness`: `enabled` (bucket set, witness armed), `unarmed` (bucket set, not armed: nothing is published), `disabled` or `unconfigured`; `last_published_at`: the latest head publication, or null; `witness_stale`: true when the witness is enabled, the chain head moved and nothing was published for more than two hours); `"schema": "newer"` (still 200) when a later release migrated the database (a well-formed revision id after this image's head); `503` with `"status": "degraded"` when the database is unreachable or its schema is behind the image, missing, or at a revision the image cannot place (`"schema": "unknown"`; `db-migrate` then exits non-zero).
- **Migrations** are expand-only within a release: a release adds tables, columns and functions and keeps what the previous release reads; removals ship in a later release. A rollback within a release is a redeploy of the previous image; a rollback across a removal is a snapshot restore. Images built before revision `019` do not recognise a newer schema, so they cannot be rolled back onto a database at `019` or later; restore the snapshot taken before the upgrade instead.
- A migration locks only what its pending revisions need (`REVISION_LOCKS` in `migrations/env.py`; a revision not listed there locks every table and the audit chain): ACCESS EXCLUSIVE on the existing tables they alter, in the portal's writer order with `audit_log` last and only when altered, then the audit chain lock, only when a revision writes audited rows. It requests each lock without waiting and, when one is in use, releases everything and tries again, for up to 5 s; `db-migrate` retries a blocked or deadlocked attempt up to 5 times, 3 s apart. Taking its locks, a migration never waits: the running release's transactions complete or wait a few milliseconds, never deadlock with it, and never queue behind a waiting migration. The revisions' own statements run with a 5 s `lock_timeout`; `REVISION_LOCKS` names every existing table they lock.
- **PostgreSQL 17** is the only dependency. The role that runs migrations must be allowed to `CREATE EXTENSION pgcrypto`.

### Git sources

The portal pulls its two repositories itself. A git source has a **role** (`governance` or `evidence`), a **provider** and a credential mode:

| Provider | `repository` | Credential modes (first is the default) |
|---|---|---|
| `codecommit` | repository name (`region` defaults to `AWS_REGION`) | `runtime_role`; `assume_role` with `credentials.role_arn` and optional `credentials.external_id` |
| `github` | `owner/name` (`options.api_url` for GitHub Enterprise Server, only with `stored_token` or `none`) | `portal_secret` (`GITHUB_TOKEN`, sent only to `https://api.github.com`); `stored_token` with `credentials.token`, Fernet-encrypted; `none` for a public repository |
| `local` | a directory inside the container | `none` |

The CodeCommit provider calls only `GetBranch`, `GetCommit`, `GetDifferences`, `GetFile` and `GetBlob` through the runtime role: no git binary and no credential helper. Stored credentials are never returned by the API.

**Default path mappings** decide which files a source reads and as what (first match wins; `*` and `?` stay within one path segment, `**` spans segments):

| Role | Pattern | Kind |
|---|---|---|
| governance | `policies/**/*.md` | `policy` |
| governance | `CLAUDE.md`, `AGENTS.md`, `README.md`, `infrastructure/**`, `agent-config/**` | `governance_document` |
| evidence | `controls.json`, `systems.json`, `tests.json`, `policy-index.json`, `vendors.json`, `risk-register.json`, `evidence/evidence-index.json` | `dataset:<name>` |
| evidence | `pentest-evidence/layer*/*.json` | `dataset:pentest-findings` |
| evidence | `decision-logs/*.jsonl`, `decision-logs/*.jsonl.manifest.json` | `decision_log` |

A source's `path_mappings` (a list of `{"pattern", "kind"}`) replaces the defaults of its role.

**A sync** resolves the branch head and ends as `unchanged` when it equals the last synced commit. Otherwise it diffs the last synced commit against head (the first sync compares the full tree blob by blob with the files already stored), reads only the changed mapped files, and processes them in dependency order, one transaction per file, so an interrupted sync resumes where it stopped:

- policies and governance documents are stored as versions (content, SHA-256, commit, blob); the public policy page renders the current version of the file named by the policy's `file_path`;
- datasets go through the diff-only import engine;
- decision logs are reassembled from their parts when chunked (no part is read beyond its declared size plus one byte) and stored by the decision-log rules; a changed part makes the sync read its manifest again;
- a deleted file is marked deleted; the findings of a deleted pentest file are removed and other records are kept.

A file the provider cannot return (over CodeCommit's 6 MB API limit) is flagged and the sync continues; the evidence repository therefore stores any file over 5 MiB as parts plus a `.manifest.json` ([docs/evidence-repo-spec.md](docs/evidence-repo-spec.md) → *Chunked files*). Each run records its commit range and `created` / `updated` / `unchanged` / `deleted` / `skipped` / `flagged` counts and ends as `success`, `partial`, `failure` or `unchanged`.

**Change records:** with `options.record_commits` (on by default for governance sources) the commits between the last synced commit and head that touched mapped paths are recorded, up to `options.history_limit` (default 500), and listed in the admin UI under **Change History**.

**Triggers:** the source's `schedule_cron`; **Sync now** in the admin UI; `POST /api/git-sources/<source>/sync` (with `{"full": true}` to re-import every mapped file at head, still diff-only per record); `python -m cli git-source sync`. At most one sync per source is queued or running.

**Cutover:** `POST /api/git-sources/<source>/last-synced-commit` with `{"commit_id": "<40-hex sha>"}`, or `python -m cli git-source set-commit --name <source> --commit <sha>`, makes the next sync diff from that commit, for a database that already holds that commit's content. A sync whose last synced commit is no longer in the repository fails with a message to run a full re-import, which resyncs from head (`{"full": true}`, `--full`, or the checkbox next to **Sync now**).

**Local directories** are read only inside `LOCAL_SOURCE_ROOTS` (resolved, symlinks followed); without it, local sources are refused in production. Errors from a GitHub host other than `api.github.com` carry only the status code and reason. Pentest findings of an evidence source are namespaced by the source, so two evidence sources never replace each other's findings. A policy whose file was deleted from the governance repository is shown as no longer published; it never falls back to another file. A disabled source's policy files are never served, and no other file replaces them. Transcripts over 32 MiB or over the entry limits (below), and chunked transcripts with a part larger than its manifest declares, are flagged `too_large` and not re-read until they change. A decision log whose repository version replaced entries submitted through the API is listed in the run's `details.conflicts`. `details.history_truncated` is true when the recorded history reached `history_limit`. Changing a source's provider, repository, branch, region or `api_url`, its role or its effective path mappings clears its last synced commit (audited), so the next sync compares the whole tree; a running sync never overwrites a last synced commit set meanwhile.

### Evidence import

The import engine compares each record built from a dataset file with the stored row and updates only the columns that differ; a file identical to what is stored issues no write at all. Every import reports `created`, `updated`, `unchanged`, `deleted` and `skipped` counts. Fields without a matching column are kept in the record's `other_data`. Records are never deleted because they disappeared from a file, except pentest findings: each `pentest-evidence/layer<N>/*.json` file is authoritative for its findings. A record that cannot be imported is skipped with an error line and the rest of the file is imported. URL columns (evidence links, vendor URLs) must be http(s) URLs; records with other values are skipped.

A local checkout goes through the same engine with `python -m cli import --data-dir <checkout>` (`--dry-run` reports the counts without writing).

### Decision logs

`POST /api/decision-log/upload?session_id=<id>&exit_reason=<reason>&agent=<agent>` takes a raw JSONL transcript as the body (a `human` or `agent` key; the request limit is 32 MiB). A session can be exported several times as it grows; the portal accepts a new export only when it extends the stored transcript, and never writes when nothing changed. The response's `status` is:

- `created` — a new session;
- `replaced` — the upload extends the stored transcript (the stored entries — role, text, tool calls, timestamp, message id, verification flag, in order — are an exact prefix of its entries and it has more); the new entries are appended and the previous version is kept as `superseded`;
- `unchanged` — an identical re-upload; nothing written;
- `kept_existing` — the upload's entries are a prefix of the stored ones; nothing written.

Any other upload answers 409 `{"error", "status": "rejected", "session_id"}`: the stored transcript is unchanged and the rejected upload is kept (gzipped) for review. Every received version is listed in the audited `decision_log_transcripts` table. A body over 32 MiB answers 413, chunked uploads included (never truncated); a transfer-coded body the server cannot delimit answers 411.

Transcripts are at most 32 MiB, whole or reassembled, hold at most 50,000 entries, each line is at most 8 MiB, and their tool calls as stored (the `tool_use` blocks as JSON, UTF-8) are at most 8 MiB per entry and 32 MiB in all; a transcript over any of these limits answers 413 `{"error"}` and nothing of it is stored. A server process imports at most 48 MiB of transcripts at once, each taking its size (an upload its Content-Length, at least 1 MiB; an upload without Content-Length and each git sync file 32 MiB): an upload that does not fit answers 429 `{"error", "status": "busy"}` with `Retry-After: 5` before its body is read, and a git sync or `cli import` waits until it fits. Only the submitting member or a compliance admin may extend a session (403); the evidence repository (git sync, `cli import`) may extend any session and is authoritative for the sessions it contains: when its version differs from entries that came through the API, or is a shorter prefix of the stored entries that the API continued, its version replaces them (the stored entries become exactly the repository's), the replaced version is kept as `superseded`, the session's submitter becomes the repository import, and the session is flagged as a conflict (`conflict`, `conflict_at`, `conflict_detail`; audited), after which only an admin may extend it through the API. A repository version that differs from entries the repository itself supplied is rejected like any other. Appended entries must not predate the latest stored entry (409). The first upload sets the session's metadata; later versions only fill unset fields, and only an admin's upload replaces them (audited). Entries are returned in transcript order. A role, message id, model, cwd or git branch that is not a string within 20/100/100/500/200 characters answers 400. Concurrent uploads of one session are serialized; the first upload of a session is created exactly once.

The response also carries the stored transcript's `content_sha256` and `content_bytes`. Transcripts in the evidence repository's `decision-logs/` follow the same rules. A user message that is exactly `done.` is flagged as a verification acknowledgment (the human's smoke-test sign-off). Entries appended through the API must not be timestamped before the latest stored entry (back-dating); the evidence repository's versions are not held to timestamp order - agent transcripts are in write order (resumed sessions, sub-agent records and compaction put earlier timestamps after later ones) - but must extend the stored entries exactly. Once the evidence repository has supplied entries of a session, only the repository may extend it: an upload by a member or an admin that would add entries gets 409 and is kept as a rejected version (audited); stored entries after the repository's are `unconfirmed` in the session detail and never count as verifications. A repository file for a session squatted through the API - one that differs from, or is a strict prefix of, the API-uploaded entries, an empty or metadata-only file included - replaces them and flags the session as a conflict (the API entries are kept as a superseded version). `GET /api/decision-log/sessions?page=&per_page=` (default 100, at most 500) lists sessions newest first as `{"items", "page", "per_page", "total", "pages"}`, each item with its `content_sha256` and `content_bytes`, so a client can skip uploading an identical file, and its `conflict` flag and `conflict_at`.

**Transcript formats and agent labels.** `app/services/transcript_ingest.py` detects the format from the records:

| Agent | Format | Stored as decision-log entries |
|-------|--------|--------------------------------|
| Claude Code | Claude Code JSONL | Every `user` and `assistant` record: its `text` blocks as the entry text, its `tool_use` blocks as the entry's tool calls |
| openclaude | Claude Code JSONL | As Claude Code |
| OpenAI Codex (TUI and `codex exec`) | Codex rollout JSONL (`session_meta`, `turn_context`, `response_item`, `event_msg` records) | Every `response_item` message with role `user` or `assistant`, with its text; every `response_item` tool call (`function_call`, `custom_tool_call`, `local_shell_call`, `web_search_call`, ...) as an assistant entry holding one `tool_use`-shaped tool call (`type`, `id`, `name`, `input`) |

Thinking and reasoning, Codex developer messages, tool output and Codex `event_msg` records are not stored. A Codex session takes its working directory and git branch from `session_meta`, its model from the first `turn_context`, and its start and end times from its first and last timestamped records; the same column limits apply (`payload.id`, `payload.model`, `payload.cwd`, `git.branch`). A new session's `agent_type` is the agent its uploader names: the upload's `agent` query parameter, or the `agent` field of a transcript's `.meta.json` sidecar (staged in `decision-logs/` or in the evidence repository). It is stored lower-case with hyphens as underscores (`claude-code` is stored as `claude_code`); an `agent` parameter that is not letters, digits, `-` and `_` within 50 characters answers 400. Without a named agent the session carries the detected format's agent: `codex` for a Codex rollout, `claude_code` for Claude Code JSONL; openclaude writes Claude Code JSONL, so an openclaude session carries the `openclaude` label when its uploader names it. A stored session keeps its label; the upload response carries it as `agent_type`.

Decision-log entries are audited per upload, not per entry: each stored version is an audited `decision_log_transcripts` row with its `entry_count` and `entries_sha256` (SHA-256 over each entry, in order, as the compact JSON array `[role, content_text, tool_calls, timestamp, message_id, is_verification]` plus a newline), so an upload adds a constant number of audit rows and holds the audit chain's lock only for those rows. `python -m cli audit-verify --decision-logs` checks every session's stored entries against its current version's `entries_sha256`, and that digest against the one the audit log first recorded for the version: it also checks that each session's version history only grows: every superseded version is a prefix of the entries that followed it (except where the evidence repository's version replaced it: reason `repository conflict: ...`, accepted only when the successor is a repository import - `source_path` set, no submitter - and the audit log recorded the supersession, the successor and the session's `conflict_at` in one transaction), entry counts never decrease, and each version still has the digest, count and content the audit log recorded when it was created and superseded. Versions are history for every role: migration 018's guard allows only a current version to become superseded, keeping its identity, counts and digests and gaining its content and reason (both required); a superseded version is frozen entirely, and every other UPDATE, DELETE and TRUNCATE is refused. An entry changed, added or removed outside an import, a digest rewritten to cover it, or a history re-baselined with a new version makes the result `broken`. Those checks rest on the portal's own records, which the application role - the role that performs imports - could forge consistently. `python -m cli audit-verify --decision-logs --against-repo [--source <evidence source>]` (also `GET /api/decision-log/verify?against_repo=true` for compliance admins, at most 500 sessions per request, resumable with `after_session`) makes the evidence repository, controlled independently of the portal, the ground truth for imported transcripts: every version recorded as a repository import (no submitter, a repository path; the successors of repository-conflict steps included) is fetched from the evidence git source at the commit the git sync recorded on it (`source_commit`), chunked files reassembled, and its SHA-256, entry count and entries digest must equal the version's - so the stored entries are the repository's - and its path must be the version's own session's file (`<timestamp>_<session id>.jsonl`, under the source's decision-log mapping; the importer and the database refuse any other at write time). A mismatch, a path that is not the session's, a commit or path the repository does not have, an unreadable file, or a commit-less import recorded after a CodeCommit or GitHub evidence source was configured is reported individually and makes the result `broken`. The legitimately commit-less cases are listed separately and make it `unverified`: `no_commit` (`cli import`, the local ingest, or a version recorded before the source was configured) and `local_history` (a local-directory source keeps no history). A SOC 2 evidence run requires `unverified` = 0: `against_repo: status=valid`. Each commit and path is fetched once, two at a time. Sessions that no repository import ever recorded (API-only sessions, or sessions restored from an earlier portal that the repository does not hold) are listed separately as `not_in_repository`. Sessions restored from an earlier portal carry no versions: a full re-import of the evidence source (`python -m cli git-source sync --name <source> --full`, or "Full re-import" on the source's admin page) BASELINES every one the repository holds identically - it records the repository's copy as the session's current version, with the commit, audited, writing no entry rows (counted as `decision_logs_baselined` on the sync run) - and applies the conflict rules to the others (nothing proves a restored session's entries came from the repository, so a differing repository file replaces them and flags the session). A session the repository has supplied shows `submitted_by` null (the repository import) and `repository_held: true`, with the member whose upload created it as `created_by`.

### Evidence collectors

| Collector | Evidence |
|---|---|
| `aws` | IAM (MFA, password policy, access keys), RDS, S3 and CloudTrail configuration |
| `git` | CodeCommit repository inventory, approval rule templates and their attachment, recent merged pull requests |
| `platform` | Health endpoints of the services you list |
| `policy` | Policy approval and review dates |
| `vendor` | Vendor inventory completeness, optional security-page checks |

Collectors are configured in the database: **Evidence Collectors** in the admin UI (with a setup wizard), or `POST /api/collectors/<name>/configure`. Credential modes are `task_role` (the portal's runtime role), `task_role_assume` (a further role assumed from it), `access_keys` (stored Fernet-encrypted) and `none`. The portal probes the permissions each collector needs; the read-only IAM policy for all of them is [iam/trust-portal-collector-policy.json](iam/trust-portal-collector-policy.json), also served by `GET /api/collectors/<name>/required-policy`. Each check's result becomes evidence linked to the test it names.

Outbound HTTP from collectors and the GitHub provider goes through `app/services/safe_http.py`: only http(s) URLs; the host is resolved and private, loopback, link-local, multicast, reserved and cloud-metadata addresses are refused, redirects are followed manually and every hop and the connected peer are checked again. These requests never go through a proxy: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `.netrc` are ignored (`REQUESTS_CA_BUNDLE` still selects the CA bundle), so every connection goes to the checked address. The platform collector may reach private hosts only for a service configured with `"allow_private": true` (metadata addresses are always refused); a GitHub Enterprise Server `api_url` on a private address is refused.

**Run now** (`POST /api/collectors/<name>/run`) queues a run and answers `202`; poll `GET /api/collectors/runs/<run_id>`. A run already queued or running answers `409` with that run: runs of one collector never overlap. Schedules are standard 5-field crontab expressions in UTC, day of week `0` = Sunday.

### Authentication and roles

- Every team member has one API key, sent as `X-API-Key: <key>` or `Authorization: Bearer <key>`. Keys are stored as SHA-256 digests and shown once, when created or regenerated. When an API-key header is present, only that key authenticates the request (a blank or invalid key is a 401, never a fall-back to the session cookie).
- In a browser, a member signs in once with the key (`/admin/login`; clients at `/admin/client-login`). The session cookie holds only the member id and a fingerprint of the current key, so regenerating the key or deactivating the member ends every session. A session ends 12 hours after sign-in, whatever the activity.
- Roles: `human` and `agent` read and write compliance data. `client` (external reviewers, with an optional expiry) is read-only and limited to the data of the client report: in the API, GET on compliance score, compliance journey, the controls list, gaps, portal settings, systems, vendors and approved policies; every other route answers 403 (drafts are 404). Compliance admins additionally use `/admin/*` and the admin-only API routes (settings updates, collectors, git sources).
- Public without a key: the published trust pages, `/api/health`, `/api/docs/`, `/api/openapi.json`, and `/setup` / `POST /api/setup` while no active admin holds an API key (the token goes in the `Authorization` header and is checked before the body is read; a token also sent in the body is a 400; creating the admin is atomic).
- **Public sections:** Admin > **Portal Settings** (or `PUT /api/settings` with `{"public_sections": [...]}`, `null` restoring the default) chooses which public pages are published: `overview`, `status`, `controls`, `policies` (approved only), `systems`, `vendors`, `risks`, `ai_transparency`, `legal`. By default every section but `risks` is published, so the risk register stays private until an admin publishes it. An unpublished section answers 404 and leaves the navigation; control names appear on the status and policy pages only while `controls` is published (otherwise `/status` shows category totals); every change is audited.
- Login, client-login and setup attempts are limited to 10 per client IP per 15 minutes, across every process: each attempt consumes one unit of a shared counter through a single atomic upsert, so concurrent attempts cannot exceed the budget; a successful sign-in clears it. A `client` member additionally starts at most 10 browser sessions per 15 minutes, counted per member whatever the IP and not cleared by signing in (429 beyond), so repeated sign-ins and logouts cannot flood the audit log.
- **Logout** ends the session everywhere: it increments the member's session epoch (audited), and every session issued under an earlier epoch, including a copied cookie, is rejected.
- The portal always keeps a durable admin: an active compliance admin holding a usable key, without an expiry or with one more than 30 days away. Deactivating an admin is refused unless another durable admin remains; an admin whose access ends within 30 days does not count.

### Audit log

- Every change to a compliance, team, settings, collector, decision-log session or version, or git-source table appends one `audit_log` row, attributed to the authenticated team member. Decision-log entries are covered by their version's audited entry count and digest.
- **Hash chain:** `row_hash = sha256(previous_hash || table_name || record_id || action || changed_by || changed_at || old_values || new_values)` (`hash_version` 2, `changed_at` as UTC ISO 8601 with microseconds). The first row links to 64 zeros, or to an ANCHOR row. A statement-level trigger takes the chain's transaction-scoped advisory lock before the statement takes any row lock, so appends are serialised and concurrent writers neither fork the chain nor deadlock.
- **Digested values:** API key digests, stored credentials, evidence file contents, transcript archives, pentest finding payloads (`other_data`), collector check details and git file content are recorded as `sha256:<hex>` only (of the raw bytes for binary columns, whatever the session's `bytea_output`). An update that changes only `updated_at` records nothing.
- **Hardened trigger functions:** they write only to `public.audit_log` (every object schema-qualified, `search_path = pg_catalog, public, pg_temp`), refuse tables outside schema `public`, and are not executable by any role but the owner. The application role cannot create temporary or schema objects.
- **Append-only:** a trigger rejects UPDATE, DELETE and TRUNCATE on `audit_log` for every role, and the application role holds only SELECT on it; the audit trigger writes the rows.
- **What the chain proves:** recomputing the chain shows that no recorded row was altered and that rows were appended in order since the chain's start. It cannot show, on its own, that the newest rows were not removed, or that someone able to act as the database owner (who can disable triggers) did not rewrite the tail and recompute it. The external witness closes that gap for everything published before such an event.
- **Arming:** the witness publishes nothing until it is armed: `python -m cli audit-witness-arm [--note TEXT]` as the owner role (`DATABASE_OWNER_*`), or `python -m cli audit-anchor --manifest` at a cutover, which arms it in the same transaction as the anchor. Arming is owner-only (`audit_witness_arm()` is not executable by the application role, and a guard trigger refuses every other write to `audit_witness_arming`), append-only and audited. A trial or shakedown database is simply never armed, so it cannot leave heads that no later chain continues; `AUDIT_WITNESS_DISABLED=true` still overrides everything.
- **External witness:** with `AUDIT_WITNESS_BUCKET` set and the witness armed, the portal publishes the chain head (row id and `row_hash`) to an S3 bucket with Object Lock, under `chain-heads/<chain id>/<YYYY>/<MM>/<DD>/<timestamp>-<row id>.json`: when the scheduler leader starts, then hourly when the head changed, and right after arming or anchoring. Each object is written with `If-None-Match: *` (the bucket policy refuses writes without it), so a published head is never replaced; when an object already exists at the head's key and differs from it, the publisher logs `audit_witness_conflict` and publishes the head under the next second's key. Every publication is recorded in `audit_witness_publications`; when the witness is enabled, the head moved and nothing was published for more than two hours, the scheduler leader logs `audit_witness_stale` every hour and the admin dashboard shows a warning; the runtime role may only put objects under `chain-heads/` (it never writes `archives/`), and Object Lock keeps them for the retention period.
- **What the witness proves:** the object KEY is authoritative: heads are grouped by the chain id in the key, and an object under `chain-heads/` whose body disagrees with its key (chain id or row id), that is over 4 KiB, not JSON, missing a well-formed `chain_id`, `id` or `row_hash`, unreadable (any S3 error, including KMS or SSE-C encryption) or not at a key of the head form is an invalid witness object, reported with its key; any invalid object makes the result `broken`. A verification with the published heads (every chain, every object version) fails when (1) a published row of the current chain is missing or different; (2) heads were published for a chain that no VERIFIED archive manifest of the current chain's anchor lineage names, with that chain's last published head (row id and `row_hash`) as its final row - the audit log was deleted, re-anchored at something else or with a replayed manifest, or recomputed from its first row; (3) heads were published but none belongs to the current chain; or (4) any invalid witness object exists. It therefore proves that every row present at a publication is still present and unchanged, and that the current chain descends from every chain ever published to the bucket. It proves nothing about rows written after the last publication (at most an hour, or since the last anchor); the rows of an archived chain are in its archive (see "Archive and anchor"). A database whose heads were published and which is then discarded (for example a trial deployment) leaves heads that no later chain continues: leave throwaway databases unarmed (`"witness": "unarmed"` in `/api/health`), or run them with `AUDIT_WITNESS_DISABLED=true`.
- **Archive and anchor:** a database whose earlier chain was archived continues it from an ANCHOR row, and the anchor is never taken on its own word. At cutover, with every writer stopped and the operator's own AWS credentials (the runtime role cannot write `archives/`): take the final dump; run `python -m cli audit-archive-manifest --dump <file> --name <name>` against the old database, which verifies its chain, hashes the dump while streaming it, uploads it to `archives/<chain id>/<name>` (or pins an object already under `archives/` with `--archive-key`), publishes the chain's final head and writes `archives/<chain id>/<name>.manifest.json` once (`If-None-Match: *`, under Object Lock); restore everything but the audit history into the new database; then run `python -m cli audit-anchor --manifest <manifest key>` with `DATABASE_OWNER_*` in the environment. The anchor command refuses a manifest that does not verify, copies the archive SHA-256, final row hash, entry count and archive name from it, records the manifest's key and SHA-256 and the anchoring role, arms the witness and publishes the new chain head. The manifest records the archive's key, version, size and SHA-256, the archived chain's id, final row id and `row_hash`, its entry count and verification summary (status, forks, true breaks, content mismatches), the archived chain's own anchor when it had one (`source_anchor`, so repeated cutovers form a verifiable lineage), and when it was written.
- **What the anchor proves:** verification accepts an anchor only when its manifest key is `archives/<chain id>/<name>.manifest.json` and the manifest names that chain and name; every version of its manifest has the SHA-256 the anchor records; the manifest's archive SHA-256, final row hash, name and entry count equal the anchor's; the archive object exists at the version the manifest pins with the stated size; the witness published the archived chain's final head (that row id and `row_hash`), no later head and no invalid object of that chain; and the manifest's own `source_anchor`, if any, verifies the same way (at most 16 generations). Each verified manifest is the only thing that lets a published earlier chain count as continued. `--rehash-archive` also streams the archive and recomputes its SHA-256. Anything else is `broken`. Emptying the audit log and anchoring it therefore needs an archive manifest written with operator credentials. `audit-verify` checks the manifest, the archive object's existence, version and size (and, with `--rehash-archive`, its SHA-256) and the old chain's published heads; it does not open the archive. What the archive CONTAINS is checked by `python -m cli audit-verify-archive --dump <file> --scratch-url <database> [--manifest <key>] [--bucket <bucket>]`: it hashes the whole dump and compares SHA-256 and size with the manifest, streams only the dump's `audit_log` into an unlogged table in a scratch schema (dropped afterwards), verifies that chain with the same rules as a live database (content hashes, links, forks, rows from before the v2 trigger), checks that its chain id, final row and row count are the manifest's, and checks every head the witness published for that chain id against it - so the archive holds every published row. It reads `pg_dump --format=custom` archives (uncompressed or gzip; PostgreSQL 12 to 17) without `pg_restore`, needs free space in the scratch database of about the `audit_log` table's size, and runs at roughly 100,000 rows per second for the load and again for the verification (about 10-20 minutes for 20 million rows). Without read access to the witness bucket (no bucket, access denied, `AUDIT_WITNESS_DISABLED`) the anchor is `unverified`, never `valid`. There is no HTTP anchor route.
- **Verification:** `python -m cli audit-verify` (unbounded) or `GET /api/audit-log/verify` (compliance admins; at most 250,000 rows per request, resumable) recomputes every hash inside PostgreSQL and reports `content_mismatches` (rows altered after they were written), `forks` (rows linked to an earlier row than their predecessor: two writers read the same chain head before writes were serialised; content intact) and `true_breaks` (links to no earlier row, or any mislink after the first serialised `hash_version` 2 row), each with its first id, and a status of `valid`, `intact_with_forks` (forks only), `unverified` (intact, but the anchor was not checked against its archive manifest), `broken` (any mismatch, true break, witness mismatch or anchor that does not match its manifest), `empty`, `no_hashes` or `unsupported`, with `anchor_verification` (`verified`, `failed` with its issues, or `unverified` with the reason). `python -m cli audit-verify --witness-s3` (with credentials that may list object versions and read them under `chain-heads/` and `archives/`; exit 2 when the bucket cannot be listed) checks the published heads and the anchor; `--witness-file <file or directory>` checks the heads only (a directory mirroring the object keys, as `aws s3 sync` writes it, or a JSON array / JSON lines of `{"key", "head"}` items), and a chain the unchecked anchor names is then only an unverified continuation (`unverified`). `POST /api/audit-log/verify` with `{"heads": [{"key": ..., "head": {...}}]}` (at most 10,000; a malformed item, or a head that disagrees with its key, is a 400) also checks the published heads, and the API checks the anchor itself from the witness bucket with the runtime role. Findings lists (witness mismatches, invalid objects, continued chains) are truncated to 100 entries, each with a `<list>_count`. Forks carry a `fork_reason`: they are rows written before the first serialized row by the earlier, unserialized trigger, with intact content. It verifies a database restored from before the v2 trigger too; long chains are verified in resumable slices (`max_rows`, `after_id`, `expected_previous_hash`).

### Web security

- Content Security Policy without inline scripts (the Swagger UI pages allow its inline bootstrap), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, a strict referrer policy, and HSTS in production; `/admin`, `/setup` and `/api/` responses are `Cache-Control: no-store`.
- Session cookie `HttpOnly`, `SameSite=Lax`, `Secure` in production.
- Cookie-authenticated POST, PUT, PATCH and DELETE requests carry a CSRF token; a request is exempt only when its API-key header authenticates. Public pages set no cookie.
- **Request limits** (`app/request_limits.py`): a request body is at most 1 MiB, except on the routes that take large bodies from an authenticated member: `POST /api/decision-log/upload` 32 MiB, `POST /api/audit-log/verify` 8 MiB, and the evidence routes that carry files (`POST /admin/evidence/upload`, `POST /api/tests/<id>/record-execution`, `POST /api/tests/batch-record-execution`, `POST /api/evidence/batch-submit`, `POST /api/evidence`, `PUT /api/evidence/<id>`) 32 MiB. An anonymous request is held to 1 MiB on every route, and the limit is in force before the CSRF check or any other hook reads the body. A body over its limit, with or without a Content-Length, answers 413 and is never truncated. Urlencoded forms are at most 500,000 bytes and 1,000 fields; a multipart text field is at most 500,000 bytes and a form at most 1,000 parts (413). A JSON body nested deeper than 32 levels answers 400 and one with more than 200,000 values 413, checked before it is parsed.
- `X-Forwarded-For` and `X-Forwarded-Proto` are trusted for `TRUSTED_PROXY_HOPS` proxies; `X-Forwarded-Host` and `X-Forwarded-Port` are not.
- Redirect targets after sign-in are same-site paths of visible ASCII characters only.
- URL fields (evidence links, vendor URLs, settings URLs) accept `http` and `https` only, and templates render any other stored scheme as `#`.
- Markdown (policies, governance documents, settings text) is rendered with raw HTML stripped and only `http`, `https` and `mailto` links kept.

## API

Interactive documentation is served at `/api/docs/` (Swagger UI) and the OpenAPI 3.0 spec at `/api/openapi.json`. Authenticate with `X-API-Key: <key>` or `Authorization: Bearer <key>`.

| Endpoint | Method | Access | Description |
|---|---|---|---|
| `/api/health` | GET | public | Database, schema and version check |
| `/api/setup` | POST | bootstrap token | Create the first admin |
| `/api/compliance-score` | GET | any key | Overall and per-category compliance scores |
| `/api/compliance-journey` | GET | any key | SOC 2 journey phases, completion and next actions |
| `/api/gaps` | GET | any key | Tests with missing or outdated evidence |
| `/api/tests/<id>/record-execution` | POST | human, agent | Record a test result, with optional evidence and files |
| `/api/tests/batch-record-execution` | POST | human, agent | Record results for many tests |
| `/api/evidence/batch-submit` | POST | human, agent | Submit evidence to many tests |
| `/api/tests/<id>/execution-history` | GET | any key | Execution history of a test |
| `/api/evidence/<id>/download` | GET | any key | Download an evidence file |
| `/api/decision-log/upload` | POST | human, agent | Upload a session transcript (Claude Code, openclaude or Codex JSONL; optional `agent` label) |
| `/api/decision-log/sessions` | GET | human, agent | Paginated session list |
| `/api/decision-log/session/<id>` | GET | human, agent | One session's entries |
| `/api/audit-log` | GET | human, agent | Query audit rows (`table`, `record_id`, `action`, `changed_by`, `since`, `limit`, `before_id`) |
| `/api/audit-log/verify` | GET / POST | admin | Verify the hash chain (250,000 rows per request); POST `{"heads": [...]}` (at most 10,000) also checks published chain heads |
| `/api/settings` | GET / PUT | any key / admin | Portal settings |
| `/api/git-sources` | GET / POST | admin | List or create git sources |
| `/api/git-sources/<source>` | GET / PUT | admin | Read or update a source (`<source>` is its id or name) |
| `/api/git-sources/<source>/sync` | POST | admin | Queue a sync (`202`, or `409` with the active run) |
| `/api/git-sources/<source>/runs` | GET | admin | Latest 100 sync runs |
| `/api/git-sources/<source>/runs/<run_id>` | GET | admin | One sync run: commit range, counts, flagged files |
| `/api/git-sources/<source>/last-synced-commit` | POST | admin | Set the commit the next sync diffs from |
| `/api/collectors` | GET | admin | Collectors and their state |
| `/api/collectors/<name>/configure` | POST | admin | Configure a collector |
| `/api/collectors/<name>/run` | POST | admin | Queue a collector run |
| `/api/collectors/runs/<run_id>` | GET | admin | One collector run and its check results |

CRUD endpoints (GET, POST, PUT, DELETE) exist for `/api/controls`, `/api/tests`, `/api/evidence`, `/api/policies`, `/api/systems`, `/api/vendors`, `/api/risks` and `/api/pentest-findings`; reads take any key, writes a `human` or `agent` key.

## CLI

`python -m cli <command>`, run inside the portal container (for example `docker exec trust-portal-dev python -m cli ...`).

Every command writes its log lines to stderr; stdout carries only the command's own output, and no command prints or logs an API key. `db-check-role` prints `OK: role <name> is safe to serve requests` (or an `UNSAFE:` line, exit 1).

| Command | Purpose |
|---|---|
| `import --data-dir DIR [--dry-run] [--dataset NAME] [--no-decision-logs] [--json]` | Import an evidence-repository checkout, datasets then decision logs, writing only differences |
| `init --data-dir DIR [--dry-run] [-v]` | Import the datasets of a checkout (no decision logs) |
| `export --output-dir DIR [--include-audit-log] [--git-commit] [--git-push]` | Export the compliance data to JSON files |
| `create-admin --name NAME --email EMAIL --key-file PATH` | Create a compliance admin; its API key is written only to `PATH` (a new file, mode 0600, never inside a git working tree) and the command prints only the path |
| `regenerate-key --member ID_OR_EMAIL --key-file PATH` | Issue a new API key for a member, written only to `PATH` like `create-admin` (the previous key stops working) |
| `audit-verify [--max-rows N] [--json] [--witness-s3 [--bucket B] [--rehash-archive] \| --witness-file PATH] [--decision-logs]` | Verify the audit-log hash chain, optionally against the published chain heads and the anchor's archive manifest, and the stored decision-log entries against their audited digests (exit 0 valid or empty, 3 intact with forks, 4 unverified, 1 broken, 2 usage or bucket not listable) |
| `audit-verify-archive --dump FILE --scratch-url URL [--manifest KEY] [--bucket B] [--keep] [--json]` | Verify what an archive dump contains: its SHA-256 and size against the manifest, its audit chain, and every published head of that chain (exit 0 verified, 1 a finding, 4 not checked against the witness or a manifest - without `--bucket` or `--manifest` it never prints `verified` -, 2 usage or unreadable dump; needs no portal configuration) |
| `audit-archive-manifest --dump FILE --name NAME [--archive-key KEY] [--bucket B]` | Archive the current database's chain with operator credentials: upload the dump under `archives/`, publish the final head, write the manifest (exit 2 when `AUDIT_WITNESS_DISABLED` is set) |
| `audit-anchor --manifest KEY [--bucket B] [--note TEXT]` | Start an empty audit log from a verified archive manifest, as the owner role (`DATABASE_OWNER_*`), arm the witness, then publish the chain head |
| `audit-witness-arm [--note TEXT]` | Arm the audit witness as the owner role (`DATABASE_OWNER_*`; audited), then publish the chain head |
| `audit-publish-head` | Publish the audit chain head to `AUDIT_WITNESS_BUCKET` now (exit 2 when the witness is disabled, unconfigured or not armed) |
| `run-jobs` | Execute queued collector runs and git syncs in this process |
| `git-source list [--json]` | List git sources |
| `git-source add --name N --role R --provider P --repository REPO [...]` | Add a git source (`--branch`, `--region`, `--credential-mode`, `--role-arn`, `--external-id`, `--token-env VAR`, `--schedule CRON`, `--disabled`, `--mappings-file FILE`, `--record-commits` / `--no-record-commits`, `--history-limit N`) |
| `git-source update --name N [...]` | Update a git source (same options as `add`) |
| `git-source set-commit --name N --commit SHA` | Set the commit the next sync diffs from |
| `git-source sync --name N [--full] [--no-wait]` | Queue a sync and run it in this process (`--no-wait` leaves it to the scheduler) |
| `scaffold --governance-dir DIR --evidence-dir DIR --company NAME [--force]` | Create governance and evidence repository skeletons |
| `db-wait [--timeout SECONDS]` | Wait for the database (container entrypoint) |
| `db-migrate` | Migrate to head and provision the application role (container entrypoint); skipped with a warning when the database is newer than the image |
| `db-check-role` | Check that the application role is safe to serve with (exit 1 when it could alter the audit trail) |

## Development and testing

Development runs in Docker; see [Try it locally](#try-it-locally). The dev container runs gunicorn with `--reload` and `PORTAL_ENV=development` on port 5100 and applies migrations at start. Schema changes are Alembic revisions in `migrations/versions/` (`001`-`020`), applied at container start by `python -m cli db-migrate`, never at application startup.

Unit tests run in Docker only. The full suite, including the PostgreSQL-backed tests (audit triggers, advisory locks, migrations), runs against a throwaway PostgreSQL 17 with a unique project name:

```bash
docker compose -p tp-test-$$ -f docker-compose.test.yml run --rm tests
docker compose -p tp-test-$$ -f docker-compose.test.yml down -v
```

The `tests` service builds the Dockerfile `test` target, sets `TEST_DATABASE_URL`, and runs pytest with coverage of `app`, `cli` and `collectors` over `tests/` and `deploy/aws/tests/`; its exit code is pytest's. Inside the dev container, `docker exec trust-portal-dev pytest` runs the SQLite-backed tests and skips the PostgreSQL-backed ones. Coverage target: 80% or more. AWS is mocked with `moto` and GitHub with `unittest.mock`; tests make no network calls.

## Self-hosting on a single server

`docker-compose.yml` runs the production image and PostgreSQL 17 on one host with Docker Compose:

```bash
git clone https://github.com/MaxGood-AI/ai-agent-first-trust-portal.git /opt/trust-portal
cd /opt/trust-portal
cp .env.example .env
# In .env set SECRET_KEY, POSTGRES_PASSWORD, BOOTSTRAP_TOKEN and COLLECTOR_ENCRYPTION_KEYS
# (see "Configuration reference" for how to generate them), and PORT=127.0.0.1:5100.
docker compose up -d --build
```

`SECRET_KEY` and `POSTGRES_PASSWORD` are required. `PORT=127.0.0.1:5100` publishes the portal on the loopback interface only, for a TLS-terminating reverse proxy on the same host (session cookies are Secure in production, and `TRUSTED_PROXY_HOPS` defaults to 1). For example, Caddy:

```
trust.example.com {
    reverse_proxy 127.0.0.1:5100
}
```

or nginx:

```nginx
server {
    listen 443 ssl;
    server_name trust.example.com;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    client_max_body_size 32m;

    location / {
        proxy_pass http://127.0.0.1:5100;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
```

Create the first admin at `https://<your-domain>/setup` with `BOOTSTRAP_TOKEN`, or with `docker exec trust-portal python -m cli create-admin --name "<name>" --email <email> --key-file <new file>`. Git sources on a single server use the `github` provider, or `codecommit` with AWS credentials in `.env`.

**Backups:** the database lives in the `pgdata` volume.

```bash
docker exec trust-portal-db pg_dump -U trust_portal trust_portal > backup_$(date +%Y%m%d).sql
```

Restore into a fresh volume before the portal starts: `docker compose up -d db`, then `docker exec -i trust-portal-db psql -U trust_portal trust_portal < backup_<date>.sql`, then `docker compose up -d`.

## License

MIT License — see [LICENSE](LICENSE) for details.
