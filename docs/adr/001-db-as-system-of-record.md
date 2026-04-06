# ADR-001: Database and API as System of Record

## Status

Accepted (2026-04-05)

## Context

The trust portal needed a clear system of record for compliance data. The portal manages controls, tests, policies, evidence, systems, vendors, risks, and pentest findings. These records were initially seeded from JSON files in the MGDataAndEvidence repository, but a decision was needed about where the authoritative version of this data lives going forward.

Five options were evaluated:

## Options Considered

**A. Git-only (JSON files in repo):** All compliance data lives as versioned JSON files. The portal reads from these files. Changes are made by editing files and committing.

**B. Git primary, DB as read cache:** JSON files are the source of truth. The database is a read cache rebuilt from files on each deployment.

**C. Dual-write (git + DB kept in sync):** Both git and the database contain the authoritative data. A sync mechanism keeps them consistent.

**D. DB primary, git as audit trail:** The database is the primary store. Git commits are generated automatically as a change log.

**E. DB + API as authoritative system of record:** The PostgreSQL database and REST API are the single source of truth. Audit logging via database triggers provides the change history. JSON files serve as bootstrap seeds for new deployments.

## Decision

**Option E** — The PostgreSQL database and REST API are the authoritative system of record for all compliance data.

## Rationale

- **Audit logging via PostgreSQL triggers** provides tamper-evident, attributed change tracking without application-level complexity
- **API-first architecture** enables AI agent integration via the trust-portal compliance skill
- **Single source of truth** eliminates sync conflicts between git and database
- **JSON seed files** (MGDataAndEvidence) still serve as bootstrap data for new deployments via the `cli init` command
- **Optional periodic export** (`cli export`, planned) can generate git-tracked backups
- **Role-based access** (admin, agent, client) is naturally expressed through the API and team member model

## Consequences

- All compliance data changes must flow through the API (or admin UI, which uses the same database)
- The `cli init --data-dir` command is for bootstrapping only, not ongoing synchronization
- MGDataAndEvidence becomes a seed/backup repository, not the live system of record
- AI agents interact via the compliance skill (not direct file editing)
- The `audit_log` table replaces git history as the change tracking mechanism for compliance data
- Every data change is attributed to a team member via the `changed_by` field
