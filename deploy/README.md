# Deploying the trust portal on AWS

Two CloudFormation templates run the portal on Amazon Lightsail. Both deploy
with the AWS CLI v2 alone (`aws cloudformation deploy`, no S3 staging bucket,
no CDK or Terraform); the scripts also need `jq` and `curl`.

- `deploy/aws/trust-portal.yaml` — the **core stack**: everything the portal
  needs to run. Adopters without CI/CD deploy only this one and use
  `deploy/aws/deploy.sh` to ship images.
- `deploy/aws/trust-portal-pipeline.yaml` — the optional **pipeline stack**:
  source → build → manual approval → deploy. It takes the core stack's name
  (`CoreStackName`) and reads everything else from the core stack's exports.

## One AWS account per environment

Run each environment (production, staging, a shakedown copy) in its own AWS
account. The environment segment keeps the names apart, but not the
authority: account-wide grants such as the collectors' reads, the Lightsail
`Get*` actions that support no resource scoping, and anyone who administers
the account reach every environment in it, and one environment's witness
bucket must never be writable by another environment's portal or operator.
A separate account gives each environment its own IAM boundary, its own
CloudTrail and its own audit evidence.

## Names

Every name starts with `<OrgPrefix>-<AppName>` (default `AppName`:
`trust-portal`) and ends with `<EnvironmentName>`; IAM roles read `<OrgPrefix>-<service>-<AppName>-<purpose>-<env>`,
naming the principal that assumes them. Bucket names also carry the account id
and region, which makes them globally unique. `OrgPrefix` is 2–8 characters,
`AppName` 2–12 and `EnvironmentName` 2–5, which keeps every name within its
service's length limit.

## What the core stack creates

| Resource | Purpose |
|----------|---------|
| Lightsail container service `…-<env>` | Runs the image; pulls from the private ECR repository through Lightsail's image-puller role when `ImageSource=ecr` |
| Lightsail PostgreSQL database `…-db-<env>` | Private, automatic backups (7-day point-in-time restore). Created with the master user (`DatabaseMasterUsername`) as owner of the database and of schema `public`, so the portal's provisioning can revoke `TEMPORARY` and `CREATE` from `PUBLIC`; the portal serves as a separate role (`DatabaseAppUsername`, which a Rule keeps different) |
| Lightsail certificate and custom domain | When `DomainName` is set; attached with `AttachCustomDomain=true`; CNAME in Route 53 when `HostedZoneId` is set |
| IAM user `…-<env>` + access key | The base credential in the container; its one permission is `sts:AssumeRole` on the runtime role |
| IAM role `<org>-user-<app>-<env>` | Runtime role, trusting the user with an external id (the stack's id). Grants exactly what the portal calls: the collector policy (`iam/trust-portal-collector-policy.json`), CodeCommit `GetBranch`/`GetCommit`/`GetDifferences`/`GetFile`/`GetBlob` on the governance and evidence repositories, `GetSecretValue` on the runtime secret, `CreateLogStream`/`PutLogEvents` on the log group, `s3:PutObject` on `<archive bucket>/chain-heads/*` (its only S3 write, and only with SSE-S3: SSE-KMS and SSE-C writes are denied, so every auditor can read the heads; an explicit deny covers `archives/*`), and for the API's anchor check `s3:ListBucketVersions` (prefixes `archives/`, `chain-heads/`) with `s3:GetObject`/`s3:GetObjectVersion` on `archives/*.manifest.json` and `chain-heads/*`. With `CollectorAssumableRoleArns` set, also `sts:AssumeRole` on exactly those roles (collectors in credential mode `task_role_assume`) |
| Secret `…-<env>` | Runtime secret: `SECRET_KEY`, `DATABASE_PASSWORD`, `BOOTSTRAP_TOKEN` (43 characters), `COLLECTOR_ENCRYPTION_KEYS` (generated) and `CLOUDWATCH_LOG_GROUP`. It never holds owner credentials or `AUDIT_WITNESS_BUCKET`. Operators add `GITHUB_TOKEN` with `set-secret-key.sh` |
| Secret `…-db-owner-<env>` | `DATABASE_OWNER_USER` and the generated `DATABASE_OWNER_PASSWORD` (the database master password). Read only at deploy; `deploy.sh` passes both to the container, whose entrypoint uses them for migrations and removes them before the server starts |
| Secret `…-credentials-<env>` | The user's access key, read by `deploy.sh` into the container environment |
| Log group `/lightsail/…-<env>` | Application and access logs, with `LogRetentionDays` |
| S3 bucket `…-archive-<env>-<account>-<region>` | Object Lock in compliance mode for `ArchiveRetentionYears`, versioned, encrypted, private, TLS only; the bucket policy denies object deletes and retention or lock changes to everyone, and denies object creation under `chain-heads/` and `archives/` without `If-None-Match` (condition key `s3:if-none-match`), so a published head, archive or manifest can never be replaced; aborts incomplete multipart uploads after 7 days; moves to Glacier Instant Retrieval after 30 days. Holds the audit chain heads under `chain-heads/` and the archives and their manifests under `archives/` |
| IAM managed policy `…-witness-verifier-<env>` | Read-only access to the heads and archives, every version, for auditors (see *The audit chain witness and archives*) |
| IAM managed policy `…-archive-operator-<env>` | The cutover operator's access: upload archives and manifests, publish the archived chain's final head, read both prefixes |
| Lambda `…-db-snapshot-<env>` + schedule | Daily snapshot `<db>-YYYYMMDD-HHMMSS`, tagged `trust-portal-stack=<stack id>`; deletes this stack's tagged snapshots of that shape once `available` and older than `SnapshotRetentionDays`, always keeping the newest `SnapshotMinimumKept` (default 7) |
| ECR repository `<org>-<app>-<env>` | `ImageSource=ecr`: scan on push, immutable tags, keeps the 30 newest images |

CloudFormation creates both secrets as an empty JSON object that never changes,
and a custom resource fills them. Its function reads which secrets and which
keys from its own environment (set by the template), never from the request,
ignores any request that is not from its own stack, and only this stack's
CloudFormation is granted permission to invoke it: it adds each missing generated key and never
regenerates a key that holds a value. After creation, a key found absent or
blank is regenerated only when it is safe to (`SECRET_KEY`, `DATABASE_PASSWORD`,
`BOOTSTRAP_TOKEN`); a blank or deleted `DATABASE_OWNER_PASSWORD` or
`COLLECTOR_ENCRYPTION_KEYS`, or a secret that no longer holds a JSON object,
fails the stack update with a message naming the key, and nothing is written.
The database, both secrets, the log group, the ECR repository and the archive
bucket are retained when the stack is deleted.

The core stack exports `OrgPrefix`, `AppName`, `EnvironmentName`,
`ContainerServiceArn`, `CredentialsSecretArn`, `OwnerSecretArn`,
`SnapshotTagValue`, `ImageRepositoryUri` and `ImageRepositoryArn` as
`<core stack name>-<output>`; the pipeline stack imports them.

## What the pipeline stack creates

| Resource | Purpose |
|----------|---------|
| Pipeline `<org>-<app>-<env>` (V2) | Source (`PipelineSource=github` through CodeConnections, or `codecommit`) → Build → manual Approval → Deploy |
| CodeBuild `…-build-<env>` | cfn-lint on both templates, the unit suite, the production image pushed to the core stack's ECR repository |
| CodeBuild `…-deploy-<env>` | `deploy.sh` against the core stack, always with an explicit witness flag: `--no-witness` while `WitnessArmed` is `false` (the default), `--witness` once an operator sets it to `true` after cutover |
| CodeConnections connection `…-<env>` | With `PipelineSource=github`; created `PENDING`, and the pipeline's only GitHub connection |
| S3 bucket `…-cicd-<env>-<account>-<region>` | Pipeline artifacts, expired after 30 days |
| EventBridge rule and role | With `PipelineSource=codecommit`: start the pipeline on a push to `SourceBranch` |

Every grant of the deploy role is scoped to the core stack: `DescribeStacks` on
that stack, `GetSecretValue` on its credentials and owner secrets, snapshots
only with its tag, deployments only to its container service. The Lightsail
reads it needs (`GetRelationalDatabase`, `GetRelationalDatabaseSnapshot`,
`GetContainerServiceDeployments`), like the snapshot function's
`GetRelationalDatabaseSnapshots`, support no resource types or condition keys
in the Service Authorization Reference, so they are granted on `*` and limited
to the stack's region.

## Runbook

Parameters go in JSON files of the form
`[{"ParameterKey": "OrgPrefix", "ParameterValue": "acme"}, …]`; see each
template's `Parameters` for every key and its default. Leave `AttachCustomDomain`,
`AccessKeySerial` and `WitnessArmed` out of the main files: a later step
overrides only that key, and the other values carry over.

1. **Deploy the core stack.** The database takes 15–20 minutes; the
   certificate is created within the first minutes.

   ```bash
   aws cloudformation deploy --region <region> --stack-name <core stack> \
     --template-file deploy/aws/trust-portal.yaml \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides file://<core-parameters.json>
   ```

2. **Validate the certificate** (with `DomainName` set). This can run as soon
   as the Certificate resource exists. With Route 53 it upserts the validation
   records; otherwise it prints them for your DNS provider.

   ```bash
   bash deploy/aws/certificate-dns.sh --region <region> \
     --certificate-name <OrgPrefix>-<AppName>-<env> --hosted-zone-id <zone-id>
   ```

   Once `aws lightsail get-certificates --region <region> --certificate-name <name> --query 'certificates[0].certificateDetail.status' --output text`
   reads `ISSUED`, attach the domain with a parameter file holding only
   `AttachCustomDomain=true`:

   ```bash
   aws cloudformation deploy --region <region> --stack-name <core stack> \
     --template-file deploy/aws/trust-portal.yaml --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides file://<attach-domain.json>
   ```

3. **Deploy the pipeline stack** (optional; needs `ImageSource=ecr`).

   ```bash
   aws cloudformation deploy --region <region> --stack-name <pipeline stack> \
     --template-file deploy/aws/trust-portal-pipeline.yaml \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides file://<pipeline-parameters.json>
   ```

   With `PipelineSource=github`, complete the
   connection: in the AWS console open *Developer Tools → Settings →
   Connections*, select the connection named by the `ConnectionArn` output,
   choose *Update pending connection*, install or select the *AWS Connector for
   GitHub* app for the organisation that owns `SourceRepository` (granting it
   that repository), and choose *Connect*. The status becomes `AVAILABLE`.

4. **Build and deploy the first image.**
   - With the pipeline: `aws codepipeline start-pipeline-execution --region <region> --name <OrgPrefix>-<AppName>-<env>`,
     then approve the *Approval* stage; the Deploy stage runs `deploy.sh`.
   - Without it: build the `production` target, push it to the
     `ImageRepositoryUri` output with a new tag (or use a published image with
     `ImageSource=public`), then:

     ```bash
     bash deploy/aws/deploy.sh --region <region> --stack <core stack> --image <image-uri> --no-witness
     ```

   `deploy.sh` snapshots the database, deploys, waits for Lightsail to report
   the deployment `ACTIVE`, and checks `/api/health` answers 200. A deployment
   that fails its health check leaves the previous one serving. A healthy
   deployment also means the serving-role check passed: in production a
   worker refuses to start when the app role could alter the audit trail
   (the full list: *Serving role* under *How it works* in the repository
   README). `python -m cli db-check-role` runs the same check and prints
   `OK: role <name> is safe to serve requests`, or an `UNSAFE:` line (exit 1)
   with the problems in its log on stderr. The container service has no
   shell, so run it from a host inside Lightsail that reaches the private
   database (the temporary instance of a restore), with `DATABASE_URL` for
   the app role.

5. **Create the first admin.** The script sends `BOOTSTRAP_TOKEN` from the
   runtime secret only as the `Authorization: Bearer` header of
   `POST /api/setup` (body `{"name", "email"}`), passing it to curl on stdin so
   it never appears in a process listing or shell history. It writes the
   returned API key to the key file (mode 600) and `<key file>.header`, prints
   only their paths, and explains a `401` (token mismatch; redeploy),
   `400` (name or email missing), `404` (an admin already exists) or `429`
   (rate-limited). The key file must not exist yet and must sit outside every
   git repository:

   ```bash
   bash deploy/aws/bootstrap-admin.sh --region <region> --stack <core stack> \
     --name "<full name>" --email <email> --key-file <path outside any repository>
   ```

6. **Connect the git sources.** In *Admin → Git sources*, or with the API, add
   the governance and the evidence repository. With CodeCommit the portal reads
   through the runtime role; with GitHub use `"provider": "github"`,
   `"repository": "<owner>/<name>"` and `"credential_mode": "portal_secret"`,
   after setting `GITHUB_TOKEN` with `set-secret-key.sh` and redeploying.

   ```bash
   curl -sS -X POST -H @<key-file>.header -H 'Content-Type: application/json' \
     --data '{"name": "governance", "role": "governance", "provider": "codecommit", "repository": "<repo>", "branch": "main", "region": "<region>", "credential_mode": "runtime_role", "schedule_cron": "*/30 * * * *", "enabled": true}' \
     <PublicUrl>api/git-sources
   ```

   Repeat with `"name": "evidence", "role": "evidence"`. `schedule_cron` is a
   5-field UTC crontab, or `null` for manual syncs only. Start a sync with
   `POST <PublicUrl>api/git-sources/<name>/sync` (answers `202` with a
   `poll_url`) and follow it at `GET <PublicUrl>api/git-sources/<name>/runs/<run id>`
   until its status is `success`, `partial`, `failure` or `unchanged`.

7. **Choose the public pages.** `public_sections` (*Admin → Settings*, or
   `PUT /api/settings {"public_sections": [...]}`, audited) lists the public
   pages; by default overview/status, controls, approved policies, systems,
   vendors, AI transparency and legal. The risk register stays private unless
   it is added.

## The audit chain witness and archives

The portal publishes its audit chain head to the archive bucket under
`chain-heads/<chain id>/…` when `AUDIT_WITNESS_BUCKET` is set: at the start of
leadership, hourly when the head changed, and right after an anchor. Every
write uses `If-None-Match: *`, so a head once published is never replaced (the
bucket policy denies a write without it; a write to an existing key fails with
412).

- **Who sets it.** `deploy.sh` puts `AUDIT_WITNESS_BUCKET` (the archive bucket)
  in the container environment. The runtime secret never carries it (the
  stack removes it, and `set-secret-key.sh` refuses it), so the environment is
  its only source.
- **Every deploy states its witness mode.** `deploy.sh` requires `--witness`
  or `--no-witness` on every run; nothing is carried over from an earlier
  run. The pipeline passes `--no-witness` until an operator sets its
  `WitnessArmed` parameter to `true` after cutover, then `--witness`.
  `--no-witness` gives the container `AUDIT_WITNESS_DISABLED=true` (the
  portal's kill switch, read from the environment only) and no
  `AUDIT_WITNESS_BUCKET`, so nothing publishes: use it for a database whose
  chain will be discarded (an empty-database shakedown), whose heads would
  later read as a replaced audit log.
- **The witness publishes only once armed.** Arming is an explicit,
  audited, owner-only action recorded in the database: `audit-anchor
  --manifest` arms it at cutover, and `python -m cli audit-witness-arm` arms
  a portal that starts with no history to carry over. A fresh database never
  publishes until then, even with `--witness`. `/api/health` reports
  `"witness"` as `disabled`, `unarmed`, `enabled` or `unconfigured`, plus
  `last_published_at` and `witness_stale`. `deploy.sh` fails a `--no-witness` deployment that is
  not `disabled`, and a `--witness` deployment that is neither `enabled` nor
  `unarmed`.
- **Archives and manifests.** At cutover the operator archives the old
  database: `python -m cli audit-archive-manifest` uploads the final dump to
  `archives/<chain id>/<name>`, publishes the archived chain's final head and
  writes `archives/<chain id>/<name>.manifest.json`; the anchor inserted into
  the new database names that manifest, and verification accepts the anchor
  only when it matches the manifest, the archive and the published heads.
  These commands run with the operator's own credentials carrying the core
  stack's `ArchiveOperatorPolicyArn` (or
  `iam/trust-portal-archive-operator-policy.json` with `ARCHIVE_BUCKET`
  replaced), never with the runtime role, which cannot write `archives/`.
- **Write-once, multipart included.** Every head, archive and manifest is
  written with `If-None-Match: *`. The bucket policy denies a `PutObject`
  under `chain-heads/` without it, and under `archives/` denies an
  object-creating request without it (`s3:ObjectCreationOperation` true:
  PutObject and CompleteMultipartUpload), so the parts of a multipart upload
  go up while completing it still needs the header. Writes that send an
  encryption header must send `AES256`, and SSE-C headers are denied; a
  request without one (an upload part, the completion) takes the bucket's
  SSE-S3 default. The S3 mock in the unit tests does not evaluate bucket
  policies, so prove these rules once per environment, before the first real
  archive, with `bash deploy/aws/archive-bucket-check.sh --stack <core stack>`
  under the operator policy (it leaves two small test objects under
  `archives/deploy-test/`, retained by Object Lock). Residual: until an
  upload completes, whoever holds the operator policy can start uploads and
  store parts under `archives/` (the lifecycle rule aborts them after 7
  days); a part is not an object and cannot replace one.
- **Verifying the witness.** `python -m cli audit-verify --witness-s3` reads
  every object version under `chain-heads/` (all chains) and the manifests
  and archives under `archives/` (`--rehash-archive` streams the archive).
  The caller needs `s3:ListBucketVersions` on the bucket for prefixes
  `archives/` and `chain-heads/`, plus `s3:GetObject` and
  `s3:GetObjectVersion` on both: attach the core stack's
  `WitnessVerifierPolicyArn` output, or, outside this template, use
  `iam/trust-portal-witness-verifier-policy.json` with `ARCHIVE_BUCKET`
  replaced by the bucket name.
- **Storage has no size limit.** No IAM or bucket-policy condition limits the
  size of a `PutObject`, so whoever holds the runtime role can store arbitrary
  data under `chain-heads/`, and Object Lock keeps it (and bills it) for
  `ArchiveRetentionYears`. Watch the bucket with the daily S3 storage metrics,
  for example these two alarms (thresholds to suit; a year of hourly heads is
  under 9,000 objects):

  ```bash
  aws cloudwatch put-metric-alarm --region <region> --alarm-name <OrgPrefix>-<AppName>-archive-objects-<env> \
    --namespace AWS/S3 --metric-name NumberOfObjects --statistic Average --period 86400 \
    --evaluation-periods 1 --threshold 100000 --comparison-operator GreaterThanThreshold \
    --dimensions '[{"Name":"BucketName","Value":"<archive bucket>"},{"Name":"StorageType","Value":"AllStorageTypes"}]' \
    --alarm-actions <sns topic arn>
  aws cloudwatch put-metric-alarm --region <region> --alarm-name <OrgPrefix>-<AppName>-archive-bytes-<env> \
    --namespace AWS/S3 --metric-name BucketSizeBytes --statistic Average --period 86400 \
    --evaluation-periods 1 --threshold 53687091200 --comparison-operator GreaterThanThreshold \
    --dimensions '[{"Name":"BucketName","Value":"<archive bucket>"},{"Name":"StorageType","Value":"StandardStorage"}]' \
    --alarm-actions <sns topic arn>
  ```

## Who can read the container environment

Lightsail stores a deployment's environment variables, including the portal's
base access key and the database owner credentials, in the container service
itself. These actions return them, so a broad read-only principal (for example
one with the AWS managed `ReadOnlyAccess` policy) is given an explicit deny on
them before the first deployment:

```json
{
  "Sid": "DenyLightsailContainerEnvironment",
  "Effect": "Deny",
  "Action": [
    "lightsail:GetContainerServices",
    "lightsail:GetContainerServiceDeployments",
    "lightsail:CreateContainerService",
    "lightsail:UpdateContainerService",
    "lightsail:CreateContainerServiceDeployment",
    "lightsail:DeleteContainerService"
  ],
  "Resource": "*"
}
```

The deploy role and the operators who deploy keep these actions. After the
first deployment, confirm CloudTrail does not record the environment of
`CreateContainerServiceDeployment` (this prints only `redacted`, `absent` or
`EXPOSED`, never the value):

```bash
aws cloudtrail lookup-events --region <region> \
  --lookup-attributes '[{"AttributeKey":"EventName","AttributeValue":"CreateContainerServiceDeployment"}]' \
  --max-results 1 --query 'Events[0].CloudTrailEvent' --output text \
  | jq -r '[.requestParameters.containers[]?.environment.AWS_SECRET_ACCESS_KEY?] | first
           | if . == null then "absent" elif test("HIDDEN") then "redacted" else "EXPOSED" end'
```

`EXPOSED` means CloudTrail event history also holds the environment: deny
`cloudtrail:LookupEvents` to the same principals, rotate the key
(`AccessKeySerial`) and change the owner password.

## Operations

- **Rotate the access key:** deploy the core stack with a parameter file
  holding only `AccessKeySerial` one higher, then redeploy the running image
  (`deploy.sh` or *Release change*). Sessions already assumed stay valid for up
  to an hour, which covers the redeploy.
- **Set an operator key in the runtime secret** (for example `GITHUB_TOKEN`):
  `bash deploy/aws/set-secret-key.sh --region <region> --stack <core stack> --key GITHUB_TOKEN --value-file <path>`,
  then redeploy.
- **Check the snapshot function:** `aws lambda invoke --region <region> --function-name <OrgPrefix>-<AppName>-db-snapshot-<env> --cli-binary-format raw-in-base64-out --payload '{"dry_run":true}' /dev/stdout`
  reports the snapshot it would take and the snapshots it would delete.
- **Archive retention is permanent.** Objects in the archive bucket cannot be
  deleted or overwritten by anyone, including the account root, until their
  retention ends; the bucket policy also denies object deletes, retention
  changes and changes to the Object Lock configuration.
- **The bucket policy itself.** An account administrator can replace or
  delete the bucket policy (S3 always lets the account change it), which
  lifts its denies on new writes. Object Lock does not depend on the policy:
  every existing version stays under COMPLIANCE retention, so no one can
  delete or overwrite a published head, archive or manifest before its
  retention ends. Organisations with AWS Organizations add a service control
  policy denying `s3:PutBucketPolicy` and `s3:DeleteBucketPolicy` on the
  archive bucket to every principal but a named break-glass role.
- **Deploy timing.** Lightsail gives a new container 300 s of failing health
  checks (10 checks, 30 s apart) before it fails the deployment. The
  entrypoint needs at most 120 s to reach the database and up to 37 s for each
  migration step blocked on a lock (5 attempts with a 5 s lock timeout, 3 s
  apart), then the migrations and the server start. `deploy.sh` waits up to
  30 minutes for the deployment.
- **Deploys interrupt running collector and sync runs.** A deployment replaces
  the container; runs in flight when the old container stops are left
  `running` without a heartbeat, and the new container's reaper marks them
  failed once their heartbeat is stale. Run them again after the deploy.
- **Rollback.** Migrations are expand-only within a release, so the previous
  image can be redeployed (`deploy.sh` with its image URI and the current witness flag, or approving an
  earlier pipeline execution). Its entrypoint finds the database at a
  well-formed revision newer than its own head, skips both the upgrade and the
  role provisioning, and `/api/health` answers 200 with `"schema":"newer"`. A
  revision the image cannot place makes the migration step exit 1 and health
  answer 503 with `"schema":"unknown"`, so that deployment fails and the
  running one keeps serving. Images older than revision 019 cannot roll back
  onto a 019+ database, and a release that contracts the schema (drops what an
  earlier release used) is rolled back only by restoring the pre-deployment
  snapshot `deploy.sh` took.
- **Local git sources stay off.** `LOCAL_SOURCE_ROOTS` is not set in the
  container environment, which disables the local-directory git provider in
  production.
- **API keys after an upgrade from an earlier portal.** Migration 017 revokes
  every API key issued before it (members keep their identities). While no
  active admin holds a key, `/setup` accepts the bootstrap token again: run
  `bootstrap-admin.sh` with a new key file, then regenerate the other
  members' keys in *Admin → Team Members*, or from a host inside Lightsail
  with `python -m cli regenerate-key --member <id or email> --key-file <path>`.
  `--key-file` is required (as it is for `create-admin`): the key is written
  only to that new file (mode 600, never overwritten, refused inside a git
  working tree), stdout carries only its path and the CLI logs go to stderr.
  In a container, write it to a path such as `/tmp/<member>.key`, copy it
  out with `docker cp` and remove the container; never print the key.
- **Moving an existing portal's audit history (cutover).** The operator runs
  each step with the archive-operator policy, one command at a time:
  (1) stop every writer to the old portal; (2) take the final dump of the old
  database; (3) `python -m cli audit-archive-manifest --dump <dump> --name <name> --bucket <archive bucket>`
  with the new image, `DATABASE_URL` pointing at the old database and no
  `AUDIT_WITNESS_DISABLED`, noting the manifest key it prints; (3a)
  `python -m cli audit-verify-archive --dump <dump> --scratch-url <scratch database> --manifest <manifest key> --bucket <archive bucket>`
  against a scratch database that can be discarded (it needs no portal
  configuration) must print `verified:`; it exits 4 and never prints
  `verified:` without `--manifest` and `--bucket`; (4) restore
  everything except the audit history into the new database; (5)
  `python -m cli audit-anchor --manifest <manifest key> --bucket <archive bucket>`
  with the new database's owner credentials (`…-db-owner-<env>`) in the
  environment; (6) `python -m cli audit-verify --witness-s3 --bucket <archive bucket>`
  prints `status=valid` and `anchor_verification=verified`; (7)
  `python -m cli db-check-role` with the app role's `DATABASE_URL` prints
  `OK:` (`UNSAFE:` stops the cutover). Once the portal serves the restored
  database: (8) sync the evidence source from the freeze commit (its
  last-synced commit set to the old portal's); (9) run a full re-import
  (`POST <PublicUrl>api/git-sources/<evidence source>/sync` with
  `{"full": true}`, *Full re-import* in the admin UI, or
  `python -m cli git-source sync --name <evidence source> --full`), which
  baselines the restored decision-log sessions; (10)
  `python -m cli audit-verify --decision-logs --against-repo` prints
  `against_repo: status=valid`; its `not_in_repository` lines (sessions no
  repository import recorded) are for review, not findings. Nothing writes
  to the old database after step 3: a later head of the old chain fails the
  anchor. Anchoring is owner-only (EXECUTE is revoked from PUBLIC; the portal
  has no HTTP endpoint for it), so steps 4-7 and 10 run from a host inside
  Lightsail that reaches the private database.
- **cfn-lint.** The Build stage runs the cfn-lint version pinned in
  `requirements-dev.txt` on both templates and fails on any warning, which
  includes W3037 (an IAM action that does not exist). Neither template
  suppresses any cfn-lint check.

## Tests

`deploy/aws/tests/` covers both Lambda functions and both templates: inline
code equals `deploy/aws/lambdas/`; collector statements equal
`iam/trust-portal-collector-policy.json`, which in turn equals the IAM actions
of the AWS operations the collectors and the git-source provider call (derived
from the source); no API name is used as an action; owner credentials stay out
of the runtime role; every pipeline import has a core export and the deploy
role reaches only the core stack's resources; Lightsail writes need the
stack's tag or resources; chain heads are write-once and a shakedown deploy
publishes none; the verifier policy reads only `chain-heads/`; the health
window covers the entrypoint's worst case; every name carries the environment
and fits its limit; outputs used by the scripts exist; both templates fit the
inline-deploy limit; cfn-lint (the pinned version) reports nothing for either
template and catches an invalid action; every action in the templates and in
`iam/*.json` exists in cfn-lint's bundled Service Authorization data. They are
part of the repository's unit suite (`pytest.ini` testpaths), which the
pipeline's Build stage runs after `cfn-lint`:

```bash
docker compose -p tp-test-$$ -f docker-compose.test.yml run --rm tests
docker compose -p tp-test-$$ -f docker-compose.test.yml down -v
```

The core template embeds the two Lambda sources as inline code; a change to
`deploy/aws/lambdas/*.py` is copied into the matching `ZipFile` block.
