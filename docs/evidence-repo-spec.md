# Evidence repository specification (format version 1)

An evidence repository is a git repository that holds an organisation's compliance data and
evidence in plain files. The trust portal pulls it through a git source with role `evidence`
and imports it into its database, writing only real differences. Any tool can produce or read
the format; this document is its contract.

`python -m cli scaffold` creates an empty repository in this layout.

Human-authored content whose change history is the evidence (datasets, policy metadata, audit
reports, hand-written decision records) lives in the repository. Machine-produced records whose
immutability is the evidence (decision logs, AI code reviews, security-assessment output and
reports, generated evidence artifacts) live in the **evidence store**, a write-once S3 bucket
under the same paths ([Evidence store](#evidence-store)). The portal imports the evidence store
alongside the repository: a git source's default mappings read every path of the
[Layout](#layout), and a source whose repository leaves pentest evidence and decision logs to the
store maps only the six authored datasets ([Path mappings](#path-mappings)).

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
| `evidence/artifacts/decisions/**` | — | Hand-authored decision records (kept in the repository, not imported) |
| `pentest-evidence/layer<N>/*.json` | dataset `pentest-findings` | One security-assessment output per file (below) |
| `decision-logs/*.jsonl` | decision log | One AI agent session export per file (below) |
| `decision-logs/*.jsonl.manifest.json` | decision log | Manifest of a chunked export (below) |
| `decision-logs/*.meta.json` | — | Optional sidecar of a transcript; its `reason` becomes the session's exit reason and its `agent` the agent label of a new session |

These are the git source's default mappings. `python -m cli import` reads the six authored
datasets (`controls.json` to `risk-register.json`) by default, and the evidence index, pentest
evidence and decision logs when they are named (`--dataset evidence`, `--dataset
pentest-findings`, `--decision-logs`). Every other path is ignored by the import.

### Path mappings

A source's `path_mappings` replaces its defaults. The evidence store imports pentest evidence
and decision logs alongside every git source (its pentest findings in its own namespace), and
the portal's records of the store's objects, with the team-only evidence documents they create,
stand beside the evidence index. A source whose repository leaves pentest evidence and decision
logs to the store maps only the six authored datasets:

```json
[
  {"pattern": "controls.json", "kind": "dataset:controls"},
  {"pattern": "systems.json", "kind": "dataset:systems"},
  {"pattern": "tests.json", "kind": "dataset:tests"},
  {"pattern": "policy-index.json", "kind": "dataset:policies"},
  {"pattern": "vendors.json", "kind": "dataset:vendors"},
  {"pattern": "risk-register.json", "kind": "dataset:risk-register"}
]
```

Its next sync marks the files it read under the other mappings deleted: the source's pentest
findings of those files are removed (a store version recorded as their `duplicate` is imported
by the store's next sync), and its evidence records and decision-log versions are kept.

`python -m cli audit-verify --decision-logs --against-repo` checks every repository-import
transcript version against the source's decision-log mapping, so a source whose repository
supplied decision logs keeps the two decision-log mappings after the six dataset mappings.

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

The format of a pentest evidence file, in the evidence store or in a repository whose source
maps it. `pentest-evidence/layer<N>/<name>.json`, where `N` is the assessment layer (1 dependency scan,
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

The format of a decision log, in the evidence store or in a repository whose source maps it
(the chunked files below exist only in a repository).

- `decision-logs/<timestamp>_<session-id>.jsonl`: an AI agent session transcript (Claude Code
  JSONL or Codex rollout JSONL export), one JSON object per line. The session id is the part after the first `_`.
- A resumed session is exported again under a new timestamp. An export replaces the stored
  transcript only when the stored entries (role, text, tool calls, timestamp, message id,
  verification flag, in order) are an exact prefix of its entries and it has more; an
  identical or prefix export changes nothing; any other export is rejected and recorded for
  review.
- A transcript is at most 32 MiB (whole or reassembled); a larger one is flagged, not imported.
  Repository exports may extend any session; they are not held to timestamp order (an agent
  transcript is in write order) and only fill unset session metadata. A role,
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

## Evidence store

The evidence store is an S3 bucket with versioning and Object Lock that the core CloudFormation
stack creates (`EvidenceBucketName` output). Producers write each record once; nothing ever
deletes or replaces it; the portal records every object's key, version id and SHA-256 in audited
tables, so the witnessed audit chain covers each one and any removal or alteration fails
verification.

### Bucket

- Versioning enabled; Object Lock default retention in **GOVERNANCE** mode for
  `EvidenceRetentionYears` years (default 7); SSE-S3 encryption, SSE-C refused; every form of
  public access blocked; object ownership enforced by the bucket owner; HTTPS only.
- The bucket policy denies to every principal: `s3:DeleteObject`, `s3:DeleteObjectVersion`,
  `s3:PutObjectRetention`, `s3:PutObjectLegalHold` and `s3:BypassGovernanceRetention`; a
  `PutObject` without `If-None-Match`; a `PutObject` with SSE-C or with a storage class other
  than `STANDARD`; `s3:ReplicateObject` and `s3:ReplicateDelete` (replication into the bucket,
  statement `DenyReplicationWrites`, which has no exception). A delete marker therefore never
  exists, and an object never carries a
  retention of its own: every version keeps the bucket default.
- The bucket policy denies `s3:PutObject` on the five store prefixes to every principal other
  than the stack's `EvidenceWriterRole` (statement `OnlyTheWriterRoleWritesEvidence`,
  `ArnNotEquals aws:PrincipalArn` naming the role): every producer, a person or not, writes only
  through that role.
- The one exception is the stack parameter `EvidenceErasurePrincipalArn` (default empty), with
  `EvidenceErasureObjectKey` (default empty). While the principal is set, the delete, retention
  and bypass denials exclude that principal on the one object `EvidenceErasureObjectKey` names
  (every version of that key) and statement `ConfineErasureToOneKey` denies it the same actions
  on every other object; with the key empty, it is denied on every object. The principal also
  needs `s3:BypassGovernanceRetention` and `s3:DeleteObjectVersion` in its own IAM policy. Both
  parameters are set only for a documented erasure (a data-subject erasure request or a
  leaked-secret purge) and cleared afterwards; both stack updates are recorded by CloudFormation
  and CloudTrail. No identity used day to day holds `s3:BypassGovernanceRetention`.

### Keys

- An object's key is the file's path in the evidence repository layout. The store holds these
  prefixes:

| Key | Kind | Portal import |
|---|---|---|
| `decision-logs/<YYYY-MM-DD>T<HHMMSS>Z_<session-id>.jsonl` | decision log | the decision-log import ([Decision logs](#decision-logs)) |
| `decision-logs/<YYYY-MM-DD>T<HHMMSS>Z_<session-id>.meta.json` | decision-log sidecar | recorded; its first version is read for the transcript's agent and exit reason when its metadata lacks them |
| `pentest-evidence/layer<1-9>/<name>.json` | dataset `pentest-findings` | the pentest-findings import in the store's namespace (below) |
| `codex-reviews/**` | evidence document `code-review` | team-only evidence document |
| `pentest-reports/**` | evidence document `pentest-report` | team-only evidence document |
| `evidence/artifacts/**` | evidence document `evidence-artifact` | team-only evidence document |

- The decision-log timestamp is a real UTC date and time (for example `2026-06-04T114334Z`);
  the session id is 1 to 100 of `A-Z a-z 0-9 . _ -`, and the decision-log import stores session
  ids of at most 36 characters that start with a letter or a digit (a transcript of any other
  session id is recorded `rejected`). A pentest file's `<name>` is 1 to 200 characters. Every
  part of a key fits the portal column that stores it.
- Any other key, and any key that is not a clean relative path (empty, over 1,024 bytes, a
  leading `/`, an empty, `.` or `..` segment, a backslash or a control character), is recorded
  as `unmapped` and imported as nothing. A key holding a control character is recorded
  percent-encoded (each control character and each `%` as `%XX`, upper-case hex) with the
  record's `key_escaped` flag set; the portal reads the version under its S3 key, and the
  administrator commands below accept either form.
- **Keys are write-once.** Every `PutObject` carries `If-None-Match: *`; the bucket policy
  refuses one without it, so a key holds exactly one version. A second version of a key, or a
  delete marker, is an anomaly that verification reports as a failure.
- A resumed session is exported again under a new timestamp, so each export is its own key,
  exactly as in the repository. A store export may only **create** a session or **extend** its
  stored entries as an exact prefix extension (the stored entries - role, text, tool calls,
  timestamp, message id, verification flag, in order - are an exact prefix of its entries and
  it has more). An identical export, or one whose entries are a prefix of the stored ones,
  changes nothing (`unchanged`). Any other export - one that differs from the stored entries at
  any entry, whether those came through the API, from the evidence repository or from the
  store - is not imported: its record is `rejected` with a detail starting `conflict:`, the
  transcript is kept as a rejected version, and it is listed for administrator review (the
  sync run's `conflicts`; verification's `store_conflicts`, informational and never a
  failure). A store export never replaces, truncates or supersedes stored entries. Store
  exports are held to the timestamp rule of repository exports (none) and only fill unset
  session metadata. A store export extends a member's session only as an exact prefix
  extension, after which members cannot extend it: once the store or the evidence repository
  has supplied entries of a session, members and admins cannot extend it through the API (409,
  kept as a rejected version). The entries the store supplied are confirmed as the store's: the
  portal records the object version they came from, and CloudTrail data events on the bucket -
  not the portal - attribute the write to the identity that assumed `EvidenceWriterRole`.
- A session restored from an earlier portal carries no transcript versions. A store export
  identical to its stored entries BASELINES it, as a full re-import of the evidence repository
  does: the export is recorded as the session's current version, linked to its object (record
  `ingested`, audited, no entry rows written), and the store has supplied its entries from then
  on; an export that is a prefix of them is `unchanged`.
- Files are stored whole: the store has no chunked files. Symbolic links are never uploaded.

### Writing an object

A producer uploads each file with one `PutObject` carrying the file's full-object SHA-256, for
example:

```
aws s3api put-object --bucket <bucket> --key decision-logs/<file> --body <file> \
  --if-none-match '*' --checksum-sha256 <base64 SHA-256 of the file> \
  --content-type application/x-ndjson --metadata '{"producer":"session-end","agent":"claude-code"}'
```

- **SHA-256 checksum, required.** The request carries `x-amz-checksum-sha256`, the base64
  SHA-256 the producer computed over the exact bytes it uploads; S3 refuses a body that does not
  match and stores the checksum with the object (a full-object checksum). A multipart upload
  with SHA-256 part checksums is accepted too: S3 checks every part against its checksum and
  stores a COMPOSITE checksum (the SHA-256 of the parts' checksums, which `HeadObject` reports
  with a `-<parts>` suffix and `ChecksumType` `COMPOSITE`). The portal reads the stored
  checksum and computes the SHA-256 of the body: a full-object checksum must equal it; for a
  composite checksum the body must have the stored size, and the record holds the body's
  full-object SHA-256 and the composite checksum as S3 reports it. An object without a SHA-256
  checksum (none, only another algorithm's, or a malformed one), or whose body does not match
  it, is recorded `non_conforming`: never imported, its body's SHA-256 and its ETag recorded, a
  verification failure until an administrator acknowledges it (below).
- **Existing key.** `412 Precondition Failed` means the key already holds an object. For a key
  the producer's local record shows it uploaded (an earlier attempt whose response was lost),
  the key is stored. For any other key, someone else wrote that key: the producer holds the
  file back and reports the conflict, and never retries it under the same key.
- **No retention headers.** A producer never sends `x-amz-object-lock-*` headers.
- **Content type** (informational): `application/x-ndjson` for `.jsonl`, `application/json` for
  `.json`, `text/markdown` for `.md`, `text/plain` for `.txt`, `.log` and `.out`, otherwise
  `application/octet-stream`.
- **Metadata** (`x-amz-meta-*`): US-ASCII printable values of at most 200 characters, at most
  2 KiB in all. The portal treats every value as untrusted: a value outside its pattern is
  dropped and noted on the object's record.

| Name | On | Value |
|---|---|---|
| `producer` | every object | what wrote it: `[a-z0-9-]{1,40}` (for example `session-end`, `code-review`, `security-scan`, `backfill`) |
| `agent` | decision-log transcripts | the agent label (`[A-Za-z0-9_-]{1,50}`, for example `claude-code`, `codex`, `openclaude`) |
| `exit-reason` | decision-log transcripts | why the session ended (`[A-Za-z0-9_.-]{1,64}`), the sidecar's `reason` |
| `session-id` | decision-log transcripts | the session id (`[A-Za-z0-9._-]{1,100}`); it must equal the id in the key |
| `redaction` | `decision-logs/` objects (transcripts and sidecars) | the identifier of the secret-redaction rule set applied before upload (`[A-Za-z0-9._-]{1,40}`) |
| `source-repo` | objects copied from an evidence repository | the repository's name (`[A-Za-z0-9._-]{1,100}`) |
| `source-commit` | objects copied from an evidence repository | the 40- or 64-hex commit the file was read from |
| `source-blob` | objects copied from an evidence repository (optional) | the 40- or 64-hex git blob id of the file at that commit; a bulk copy omits it, the blob being `<source-commit>:<key>` |

- The portal accepts every name of the table on every object, whatever its kind: a bulk copy
  puts the same metadata on every object of a folder, so a `decision-logs/` sidecar carries
  `producer`, `redaction`, `source-repo` and `source-commit` like its transcript. A name outside
  the table is dropped and noted.

- A transcript's agent and exit reason come from its `agent` and `exit-reason` metadata, else
  from the first version of its sidecar object (the version id read is recorded on the
  transcript's record), else from the detected format.

### Producers

- **Redaction is a hard gate for decision logs.** A producer runs its secret-redaction rule set
  over a transcript before upload and sets `redaction`; when redaction fails or a secret
  pattern remains, it uploads nothing and holds the transcript back for review.
- Every other object is scanned for secrets before upload; a file with a finding is held back,
  never uploaded with the secret.
- A producer keeps a local record of what it uploaded (key, SHA-256, version id) and of what
  is pending, and retries pending uploads until they succeed, so evidence produced offline is
  uploaded later and nothing is uploaded twice.
- A producer keeps the list of erased keys (committed in the evidence repository) and never
  uploads a listed key again.
- Copying an evidence repository's files into the store keeps each file's bytes and names
  where they came from (`source-repo` and `source-commit`; `source-blob` is optional, the blob
  being `<source-commit>:<key>`), so the copy is checkable against the repository: the object
  equals that blob, or, for a transcript the redaction changed, that blob after the rule set
  named in `redaction`.
- A bulk copy first builds a local copy of the files at one commit: each file whole (a chunked
  file reassembled), transcripts redacted with the producer's rule set, files with secret
  findings left out for review. It then sets the writer profile to upload every file up to
  5 GB in one `PutObject`, once:

  ```
  aws configure set s3.multipart_threshold 5GB --profile <writer profile>
  ```

  and copies each folder of the local copy (a store prefix, for example `decision-logs` or
  `pentest-evidence`) with one command, run as the writer role:

  ```
  aws s3 cp <dir>/<folder> s3://<bucket>/<folder> --recursive --no-overwrite \
    --no-follow-symlinks --checksum-algorithm SHA256 \
    --metadata '{"producer":"backfill","source-repo":"<repo>","source-commit":"<commit>"}' \
    --profile <writer profile>
  ```

  The `decision-logs` command's metadata also carries `"redaction":"<rule set id>"`, on its
  transcripts and sidecars alike.
  `--no-overwrite` sends `If-None-Match` on every write, so a re-run uploads only what is
  missing.

### Who may read and write

| Identity | Access |
|---|---|
| Producers (people, workstations and non-human producer identities) | the stack's `EvidenceWriterRole` (`EvidenceWriterRoleArn` output), the only principal the bucket policy lets write the store prefixes. It holds only the evidence-writer policy (`EvidenceWriterPolicyArn` output): `s3:PutObject` on the five key prefixes above; no read, list, delete or retention action. Its trust policy admits only the IAM users and roles of the stack's account named in the stack parameter `EvidenceWriterPrincipalArns` (exact `aws:PrincipalArn` match; empty, the default, admits nobody), each of which also holds `EvidenceWriterAssumePolicy` (`EvidenceWriterAssumePolicyArn` output) to assume it; a person uploads through an AWS CLI profile that assumes the role with the person's name as the session name, and a non-human producer assumes it with its own name as the session name, so CloudTrail data events attribute each write, never through an everyday identity |
| The portal's runtime role | list object versions, read object versions and their retention, read the bucket's versioning, Object Lock configuration, bucket policy and lifecycle configuration; every write is denied |

- The bucket policy binds every principal that has no exception in it. An account
  administrator can still change the bucket's configuration (its policy, its default retention,
  its lifecycle) and, after removing the policy's denials, its versions. The portal does not
  attribute writes, configuration changes or deletions; it detects them (below). The
  account-level controls are a service control policy that protects the bucket's configuration
  and CloudTrail data events on the bucket, which attribute every write and delete
  (`deploy/README.md`).

### Portal import and verification

- The portal reads the bucket named by `EVIDENCE_STORE_BUCKET` through its runtime role. A sync
  (on the scheduler leader when it gains leadership and then every hour; admin **Sync now**,
  API or CLI) first records the bucket's default retention (mode
  and period in days, a year counting 365) on its run (audited, written once). The bucket's
  first sync also sets its **retention floor** to that period: the lowest default retention
  verification accepts, changed afterwards only by an administrator (below). The sync then
  lists every object version under the store's prefixes, a page at a time (a prefix whose
  listing fails is an error of the run, by class and code, and the sync goes on with the next
  prefix; the run is `partial`, or `failure` when no prefix could be listed), and processes
  the first version of each key that it has not recorded, one at a time, within per-kind size
  limits (decision logs
  32 MiB, sidecars 64 KiB, pentest evidence 16 MiB, evidence documents 256 MiB; checked before
  any byte is read). It records the bucket, key, version id, SHA-256 (the stored full-object
  checksum; the body's for a composite checksum and for a `non_conforming` version within its
  limit), the stored composite checksum, size, ETag, last-modified time,
  content type, metadata, Object Lock mode and retain-until date, kind, status and recording
  sync run of each: `ingested`, `unchanged`, `recorded`, `duplicate`, `rejected`,
  `non_conforming`, `too_large`, `error`, `acknowledged` or `erased`. A later version of a key
  and a delete marker are listed on the sync run and never imported. The portal never removes a
  record because of the store.
- The bucket's retention floors are appended, never changed or deleted: each change is a new
  row dated by the database clock (a date the writer sends is ignored), the latest row is the
  floor, the first is the one the bucket's first sync set, and every later one names the
  administrator who set it and the reason. Sync runs and records are dated by the database
  clock too (a run's queue time and a record's creation time never change).
- JSON content (pentest files, sidecars, each transcript line) is parsed within 64 levels of
  nesting, and pentest files and sidecars within a bounded number of values. Before any write,
  each version's content passes a pure, total check that decides from its body alone (and, for
  a transcript, the agent and exit reason its metadata or sidecar supplies) whether it can be
  imported: content that is invalid or too deeply nested, or that holds a value the database
  could refuse - text with a NUL character or an unpaired surrogate anywhere (JSON member names
  included), a non-finite number, a date-time whose UTC instant falls outside the years 1 to
  9999, a value of a type its column does not take, a transcript field longer than its column -
  is recorded `rejected` (`too_large` over a transcript limit) once, with the reason; a pentest
  finding with a value longer than its column is skipped, as every pentest import skips it, and
  a transcript's exit reason is cleaned (NUL characters and unpaired surrogates replaced by
  U+FFFD) and cut to its column. A refusal of the import's plan against the database (a
  conflict: `rejected`, detail `conflict: ...`) is the only other refusal. A version a sync
  cannot read or write for any other reason (S3, network, any database error) is recorded
  `error` and read again by every sync until it imports; it is never recorded as a refusal of
  its content. Run details name an error by its class and code only.
- **Pentest evidence.** The store imports a pentest file only into its own namespace and never
  changes the findings of an evidence repository or of `cli import`; their imports never skip a
  file because the store holds it. When another source holds findings for the same
  `layer<N>/<name>.json` with exactly the identity of the store's file (the same findings, each
  identified by its canonical SHA-256 and ordinal) and the file has findings, the version is
  recorded `duplicate`, naming that source, and nothing is imported; every sync re-evaluates
  the duplicates whose source no longer holds those findings - recomputed from that source's
  findings' content, so a finding it deleted, edited or re-keyed counts - and imports them
  then. Otherwise the file's findings are inserted into the store's namespace (the record holds
  their count and identity); when another source holds different findings for that path, both
  are kept and the sync run lists the conflict. A file without findings to store, or whose
  findings the store's namespace already holds exactly (another store object of the same path),
  is `unchanged`; one whose findings it holds differently is `rejected` (`conflict:`): the store
  never replaces its own findings.
- The store only inserts findings: each id derives from the store's `source_file`, the object's
  S3 version id (unknowable before the upload), the finding's canonical SHA-256 and its
  ordinal, so no writer can hold an id the store will use before the object exists, and an id
  already held by a stored finding is `rejected` (`conflict:`), never taken over or moved. A set
  of findings is identified, in every namespace, by its content (each finding's canonical
  SHA-256 and ordinal), never by ids. The store's namespace holds a path's findings for the
  store object that imported them; findings there that no store object imported are not the
  store's: they never suppress an import, and verification fails them.
- The store's pentest findings (`source_file` `evidence-store:<path>`) are immutable: the API
  answers 409 to changing, deleting or creating one, and migration 021's guard refuses the same
  for every database role. The API assigns the id of every pentest finding it creates (a body
  naming an `id` answers 400).
- Evidence documents (`code-review`, `pentest-report`, `evidence-artifact`) are visible to team
  members only, never on a public page; administrators link them to controls and tests. The
  portal serves a document's bytes from the store and only after their SHA-256 matches the
  record.
- `python -m cli audit-verify --evidence-store` (also `GET /api/evidence-store/verify`, in
  slices of at most `max_items` records and 256 MiB of bodies read - a slice always checks at
  least one record and reports `budget_exhausted` when it stops at a budget; a run through the
  API is the sum of its slices; the CLI checks everything with bounded memory and reports
  `rederived` and `bytes_read`) verifies:
  - **the bucket:** versioning is enabled; Object Lock has a default retention in `GOVERNANCE`
    or `COMPLIANCE` mode whose period is no lower than the bucket's retention floor (a bucket
    with records and no floor fails; raising the default, and restoring it to the floor or
    above after lowering it, verifies); the bucket policy denies to every principal
    `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:BypassGovernanceRetention` and
    `s3:PutObjectRetention`, and a `PutObject` without `If-None-Match`, on every one of the five
    store prefixes; no lifecycle rule has an `Expiration`, `NoncurrentVersionExpiration`,
    `Transitions` or `NoncurrentVersionTransitions` action (`AbortIncompleteMultipartUpload` is
    allowed). A policy statement counts only with `Effect` exactly `Deny`, `Principal` `"*"` (or
    `{"AWS": "*"}`), no `NotAction`, `NotResource` or `NotPrincipal`, actions naming each
    required action exactly or by a wildcard that matches it (`s3:*`, `s3:Delete*`), and object
    resources exactly `arn:<partition>:s3:::<bucket>/*` (every prefix) or
    `arn:<partition>:s3:::<bucket>/<literal>*` (the store prefixes that start with the literal,
    which holds no `*` or `?`), where `<partition>` is the partition of the region the portal
    runs in (`aws`, `aws-cn` for `cn-*`, `aws-us-gov` for `us-gov-*`); any other resource
    protects nothing. Statements beyond the required denials (the writer-role denial among
    them) never fail the check. The denials carry no condition, or only the documented erasure
    exception (`ArnNotEquals aws:PrincipalArn` naming literal ARNs; a `*`, `?` or `$` - a
    wildcard or a policy variable - there fails); the `If-None-Match` denial carries only
    `Null s3:if-none-match: true` (with at most `Bool s3:ObjectCreationOperation: true`). A
    policy that is not JSON or repeats a key in any object fails. While the bucket policy names
    an erasure principal, the result is `unverified` and names that principal; the bucket's
    first retention floor is the default retention its first sync observed and no lower than
    the Object Lock retention, from its upload, of the earliest version the portal recorded in
    the bucket (less one day, and one more per four years for leap days), and every lowering of
    the floor is listed (`retention_floor_lowerings`, informational, attributed by the
    witnessed audit log);
  - **every record, against its own recorded bucket:** the version exists, its stored SHA-256
    checksum (the full-object one, or the composite one, as recorded), size and ETag equal the
    record, it is under Object Lock with a retain-until date
    no earlier than the recorded one, and its retention from its upload (retain-until minus the
    `LastModified` that `HeadObject` reports) is at least its bucket's retention floor, less
    one day (`--full` also re-reads every body and recomputes its SHA-256). A version whose
    retain-until date has passed is listed as `retention_expired` (informational);
  - **every record's import outcome**, with the store as the ground truth: every outcome that
    is not a straightforward import is re-derived from the version's body on every run (no
    `--full` needed; the body is read within its kind's limit by a pool of workers, nothing is
    written) with the sync's own content check and plan and the same inputs (a transcript's
    agent and exit reason from its metadata or the sidecar version its record names, re-read). Its kind
    is its key's (an `unmapped` record is re-derived from its key alone) and its status one a
    sync gives that kind; an `ingested` decision log has a current or superseded transcript
    version of its session imported from it with its SHA-256; an `ingested` pentest file has
    exactly the findings it recorded importing in the store's namespace, under the ids its
    version gives them, and no other finding of its file (their count and identity recomputed
    from the findings' content; `--full` also re-derives them from the body). From the body: an `unchanged` decision log's entries are identical to, or a prefix of,
    its session's stored entries; an `unchanged` pentest file has no findings to store, or the
    store's namespace holds exactly them; a `duplicate`'s counterpart holds exactly the findings
    of its body and of its record, recomputed from the counterpart's content; a `too_large`
    version is over its kind's limit by the size `HeadObject` reports (a decision log: or its
    body over a transcript limit); a `rejected` version is still refused by its content check
    or its plan (a decision log by a dry run with the store's authority; a version of another
    kind is never refused for its content). Every refusal (`rejected`, `too_large`) is listed
    (`refusals`), and one that does not re-derive is a failure, which an administrator settles
    by acknowledging it (below). An `acknowledged` non-conforming version is still
    non-conforming by its own `HeadObject`;
  - **the store's pentest findings:** every `source_file` of the store's namespace is held by a
    store object that imported it (its ingested record, or that record since erased, with as many
    findings); any other finding there is a failure;
  - **every evidence document** against its object record, and every ingested evidence-document
    record against its document;
  - **the store conflicts** (informational, never a failure): the decision-log exports refused as
    conflicts, listed as `store_conflicts` for administrator review;
  - **the listing:** every object version under the store's prefixes against the records (a
    prefix whose listing fails is a failure, named by its error's class and code).
- Verification therefore detects the removal or alteration of any recorded version, a default
  retention below the floor, an object retained for less than the floor, a bucket policy without
  the denials, a lifecycle rule that expires or transitions versions, a record whose import
  never happened, and an outcome - a refusal included - that the object's body does not prove,
  whether a writer or the portal's own database role recorded it. A missing, changed or
  unlocked version, a bucket failing a check above, a delete marker, a second version of a key,
  a `non_conforming` record, an erased record whose version still exists, an import outcome
  the database does not hold or the body does not re-derive, a store-namespace finding no store
  object imported, or a document that differs from its record is a failure; a version the
  portal has not recorded yet is `unrecorded` and a version recorded as `error` is `pending`
  (never a failure). A SOC 2 evidence run requires status `valid`
  (failures = 0, unrecorded = 0, pending = 0, no erasure principal), after a sync; it needs no
  `--full`.
- `python -m cli audit-verify --decision-logs --against-store` (also `GET
  /api/decision-log/verify?against_store=true`, a window of sessions per request) checks every
  decision-log version imported from the store against its object: the object is a decision
  log of the version's session, its recorded SHA-256 equals the version's content SHA-256, it
  verifies in the store, and its body - that exact version, read streamed within the
  transcript limits - hashes to that SHA-256 and parses (as the import parses it) to the
  version's entry count and entries digest. A mismatch, a missing record or object and an
  unreadable body are failures; erased objects are listed separately. Versions imported from an
  evidence repository are checked with `--against-repo`. `audit-verify --decision-logs` fails a
  current or superseded version that names a store object not recorded as `ingested` (or
  `erased`), and a `repository conflict:` step whose successor is a store import: the store
  never replaces entries.
- An erased version (documented erasure, above) is marked on its record with
  `python -m cli evidence-store record-erasure --key K --version-id V --reason TEXT --admin
  ID_OR_EMAIL [--bucket B]` (an active compliance administrator; the reason is required;
  `HeadObject` of that exact version must report it absent; audited). Verification lists erased
  versions separately and fails an erased record whose version exists.
- A version an import cannot settle is acknowledged with `python -m cli evidence-store
  acknowledge --key K --version-id V --reason TEXT --admin ID_OR_EMAIL [--bucket B]` (same rules;
  audited): a `non_conforming` version; a refusal (`rejected` or `too_large`) that no longer
  re-derives from its body (it is re-derived first; a refusal that still holds is refused); an `error`
  version that failed at least 3 syncs. Many are acknowledged at once with `--file PATH` in
  place of `--key` and `--version-id`: JSON lines `{"key": K, "version_id": V}`, each
  acknowledged on its own by the same rules with its own audited change, and a summary of what
  was acknowledged and refused. The record keeps the status it was acknowledged from
  (`acknowledged_from`). Verification lists acknowledged versions separately (informational)
  and still checks that each exists with the recorded size, ETag and SHA-256 (a non-conforming
  one: SHA-256 with `--full`).
- A bucket's retention floor is set with `python -m cli evidence-store set-retention-floor
  --days N --reason TEXT --admin ID_OR_EMAIL [--bucket B]` (same rules; audited; a new floor row,
  after the bucket's first sync has set its first floor), the only way to lower it.
- `--bucket` (default: `EVIDENCE_STORE_BUCKET`) names the bucket a record was recorded in, so
  the records of a former bucket can be handled. These commands run in an operator shell with
  the portal's database credentials: `--admin` names the compliance administrator the audited
  change is attributed to, as the operator asserts it, and the audit log records the change,
  its reason and that administrator.
- The records are evidence for every database role: a record's bucket, key (and its
  `key_escaped` flag), version id, kind and creation time never change, its SHA-256, composite
  checksum, size, ETag, dates, metadata and Object Lock state change only while a sync reads it again
  (`error`), its status changes only from `error` to a recorded status, from `duplicate` to
  `ingested`, `unchanged`, `duplicate` or `rejected`, from `non_conforming`, `rejected`,
  `too_large` or `error` to `acknowledged`, and from any status to `erased`; an evidence document's object,
  kind, key, SHA-256 and size never change; a sync run's bucket and queue time never change and
  the retention it read is written once; retention floors are appended, never changed; none of
  them is ever deleted; and the store's pentest findings never change and are never deleted.

## Versioning

The format version changes only for incompatible changes; the portal reads every version it
lists here.
