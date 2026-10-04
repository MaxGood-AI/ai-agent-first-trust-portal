# Evidence repository specification (format version 1)

An evidence repository is a git repository that holds an organisation's compliance data and
evidence in plain files. The trust portal pulls it through a git source with role `evidence`
and imports it into its database, writing only real differences. Any tool can produce or read
the format; this document is its contract.

`python -m cli scaffold` creates an empty repository in this layout.

## Marker

`/.evidence-repo.json`:

```json
{"format": "trust-portal-evidence-repo", "version": 1}
```

## Layout

| Path | Kind | Content |
|---|---|---|
| `controls.json` | dataset `controls` | JSON array of controls (`cli/schemas/controls.schema.json`) |
| `systems.json` | dataset `systems` | JSON array of systems (`cli/schemas/systems.schema.json`) |
| `tests.json` | dataset `tests` | JSON array of control tests (`cli/schemas/tests.schema.json`) |
| `policy-index.json` | dataset `policies` | JSON array of policy metadata (`cli/schemas/policies.schema.json`) |
| `vendors.json` | dataset `vendors` | JSON array of vendors (`cli/schemas/vendors.schema.json`) |
| `risk-register.json` | dataset `risk-register` | JSON array of risks (`cli/schemas/risk-register.schema.json`) |
| `evidence/evidence-index.json` | dataset `evidence` | JSON array of evidence records (`cli/schemas/evidence.schema.json`) |
| `evidence/artifacts/**` | — | Evidence files referenced by `file_path` in the evidence index (not imported) |
| `pentest-evidence/layer<N>/*.json` | dataset `pentest-findings` | One security-assessment output per file (below) |
| `decision-logs/*.jsonl` | decision log | One AI agent session export per file (below) |
| `decision-logs/*.jsonl.manifest.json` | decision log | Manifest of a chunked export (below) |
| `decision-logs/*.meta.json` | — | Optional sidecar of a transcript; its `reason` becomes the session's exit reason and its `agent` the agent label of a new session |

Every other path is ignored by the import. A portal administrator can replace these default
mappings per source (`path_mappings`).

## Datasets

- Each dataset file is a JSON array of objects. Keys that match a portal column are stored in
  that column; every other key is kept in the record's `other_data`.
- URL fields (evidence `url`, vendor URL columns) must be http(s) URLs; a record with another
  value is skipped with an error line.
- Records carry a stable `id` (controls, systems, tests, policies, vendors, risks). Evidence
  records are identified by `test_name` + `file_path` + `collected_at`.
- Import order is `controls`, `systems`, `tests`, `policies`, `vendors`, `evidence`,
  `risk-register`, `pentest-findings`, then decision logs, so references resolve.
- A record whose stored values already equal the file's values is not written. A record that
  disappears from a dataset file is kept in the portal (the portal database is the system of
  record; removing data is an explicit portal action).
- `policy-index.json` entries set `file_path` to the policy's path in the governance
  repository (for example `policies/access-control-policy.md`); leading `../` segments are
  ignored, so paths written relative to a sibling checkout resolve too.

## Pentest evidence

`pentest-evidence/layer<N>/<name>.json`, where `N` is the assessment layer (1 dependency scan,
2 static analysis, 3 endpoint testing, 4 AI-assisted assessment):

```json
{
  "scan_id": "<uuid shared by all outputs of one scan>",
  "repo": "<repository name, may be empty>",
  "timestamp": "2026-04-16T193413Z",
  "analyzer": "<tool name, optional>",
  "finding_count": 2,
  "findings": [ { "severity": "HIGH", "summary": "...", "remediation": "...", "file_path": "...", "soc2_controls": ["CC7.1"] } ]
}
```

- A file without a `findings` array (for example a scan summary) imports nothing.
- Each file is authoritative for its own findings: the portal holds exactly the findings the
  file lists, identified by the file path, the SHA-256 of the finding's canonical JSON and an
  ordinal among identical findings in that file. Reordering a file changes nothing; deleting a
  file removes its findings.
- Files are append-only in practice: a new scan writes new files.

## Decision logs

- `decision-logs/<timestamp>_<session-id>.jsonl`: an AI agent session transcript (Claude Code
  JSONL or Codex rollout JSONL export), one JSON object per line. The session id is the part after the first `_`.
- A resumed session is exported again under a new timestamp. An export replaces the stored
  transcript only when the stored entries (role, text, tool calls, timestamp, message id,
  verification flag, in order) are an exact prefix of its entries and it has more; an
  identical or prefix export changes nothing; any other export is rejected and recorded for
  review.
- A transcript is at most 32 MiB (whole or reassembled); a larger one is flagged, not imported.
  Repository exports may extend any session, but may not back-date entries (an appended entry
  must not predate the latest stored one) and only fill unset session metadata. A role,
  message id, model, cwd or git branch must be a string of at most 20/100/100/500/200 characters.
- `<stem>.meta.json` (optional): `{"session_id", "cwd", "reason", "agent", "exported_at", "transcript_file"}`; `agent` (for example `claude-code`, `openclaude`, `codex`) labels a new session, which otherwise carries its detected format's agent.

### Chunked files (any file over 5 MiB)

Git hosting APIs limit the size of one file they return (AWS CodeCommit: 6 MB per file through
its API). A file larger than 5 MiB (5,242,880 bytes) is therefore stored as byte-slices plus a
manifest in the same directory, instead of as one file:

```
decision-logs/2026-06-04T114334Z_<session-id>.jsonl.manifest.json
decision-logs/2026-06-04T114334Z_<session-id>.jsonl.part-0001
decision-logs/2026-06-04T114334Z_<session-id>.jsonl.part-0002
...
```

```json
{
  "format": "chunked-file/v1",
  "name": "2026-06-04T114334Z_<session-id>.jsonl",
  "size": 22821783,
  "sha256": "<SHA-256 of the whole file>",
  "parts": [
    {"name": "2026-06-04T114334Z_<session-id>.jsonl.part-0001", "size": 5242880, "sha256": "<hex>"}
  ]
}
```

- Parts are consecutive byte ranges of the original file, each at most 5 MiB; concatenated in
  manifest order they reproduce the file exactly (`size` and `sha256` must match).
- Part names are plain file names in the manifest's directory.
- Writers split with `app.services.chunked_files.split()`; readers reassemble with
  `reassemble()`, which verifies every part and the whole.
- Files of 5 MiB or less are stored whole.
- A manifest is at most 1 MiB, lists at most 32 parts and describes at most 128 MiB; a
  manifest over any limit is rejected.

## Versioning

The format version changes only for incompatible changes; the portal reads every version it
lists here.
