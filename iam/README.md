# Trust Portal — AWS IAM policies

`trust-portal-collector-policy.json` is the read-only IAM policy the evidence
collectors need, and nothing more: every action in it is one the collectors or
the collector permission check (`app/services/permission_prober.py`) call.
The portal's collector setup screen and
`GET /api/collectors/<name>/required-policy` read it at runtime to show exactly
what to grant, and the AWS deployment template grants it to the portal's
runtime role. `deploy/aws/tests/test_iam_actions.py` derives the called
operations from the code and fails when the policy and the code disagree.

## Where it is granted

- **AWS deployment (`deploy/aws/trust-portal.yaml`).** The runtime role carries
  every statement of this file (its tests keep the two identical), with the
  per-repository CodeCommit statement scoped by the `CollectorRepositoryPattern`
  parameter. The portal reaches AWS as that role through collector credential
  mode `task_role`. See `deploy/README.md`.
- **Any other hosting.** Attach the policy to the identity the portal uses:
  an IAM role assumed by the container, or an IAM user whose access keys are
  given to a collector in `access_keys` credential mode.

## What the permissions cover

Each `Sid` maps to one service, all read-only:

- `TrustPortalCollectorSTS` — identity detection (`sts:GetCallerIdentity`)
- `TrustPortalCollectorIAMReadOnly` — users, access keys, MFA devices (assigned and virtual), password policy
- `TrustPortalCollectorRDSReadOnly` — database instances
- `TrustPortalCollectorS3ReadOnly` — bucket list, default encryption, versioning, public access block
- `TrustPortalCollectorCloudTrailReadOnly` — trails and trail status
- `TrustPortalCollectorCodeCommitList` — repository list (git collector)
- `TrustPortalCollectorCodeCommitRepositories` — each repository's default branch and its commits (git collector)

Removing a statement removes that coverage; the matching checks then report
`skipped` or `error` and the portal keeps running.

## Witness verifier policy

`trust-portal-witness-verifier-policy.json` is the read-only policy for an
auditor who verifies the published audit chain heads and the archives with
`python -m cli audit-verify --witness-s3`: `s3:ListBucketVersions` on the
archive bucket for prefixes `archives/` and `chain-heads/`, and `s3:GetObject`
and `s3:GetObjectVersion` on both. Replace `ARCHIVE_BUCKET` with the bucket
name. The AWS deployment creates the same policy as a managed policy (the core
stack's `WitnessVerifierPolicyArn` output).

## Archive operator policy

`trust-portal-archive-operator-policy.json` is for the cutover operator who
runs `python -m cli audit-archive-manifest` and `python -m cli audit-anchor`
with their own credentials: `s3:PutObject` and `s3:AbortMultipartUpload` on
`archives/*` (the dump goes up as a multipart upload), `s3:PutObject` on
`chain-heads/*` (the archived chain's final head), and the same reads as the
verifier. The portal's runtime role never gets it: its only S3 write is
`chain-heads/*`, and it is explicitly denied writes to `archives/*`. The AWS
deployment creates it as a managed policy (`ArchiveOperatorPolicyArn`).
`deploy/aws/tests/test_iam_actions.py` keeps it equal to the S3 operations the
witness and archive code calls.

## Evidence writer policy

`trust-portal-evidence-writer-policy.json` is the permission policy of the
evidence writer role, the role every upload of evidence store objects is
made as (decision logs, code reviews, pentest evidence and reports, and
evidence artifacts): `s3:PutObject` on the store's five key prefixes
(`decision-logs/`, `codex-reviews/`, `pentest-evidence/`, `pentest-reports/`,
`evidence/artifacts/`) and nothing else, so an uploader cannot read, list,
delete or change the retention of anything. Replace `EVIDENCE_BUCKET` with
the bucket name. The bucket policy denies `s3:PutObject` under those
prefixes to every principal but the writer role (`OnlyTheWriterRoleWritesEvidence`,
`ArnNotEquals aws:PrincipalArn` the role's ARN), so every producer, a
non-human one included, assumes the role and uploads as its session. The
bucket policy also holds the write rules every upload meets
(`If-None-Match: *`, SSE-S3 only, storage class `STANDARD`); the producer
contract is `docs/evidence-repo-spec.md` → "Evidence store". The AWS
deployment creates the same policy as a managed policy (the core stack's
`EvidenceWriterPolicyArn` output) and attaches it, as its only permission,
to the evidence writer role (`EvidenceWriterRoleArn`).
`deploy/aws/tests/test_evidence_store.py` keeps the file and the managed
policy identical. The portal's runtime role never holds it: it lists and
reads the store's object versions, their retention and the bucket's
versioning, Object Lock configuration, bucket policy and lifecycle
configuration, exactly the S3 operations
`app/services/evidence_store/` calls (`deploy/aws/tests/test_iam_actions.py`),
and is explicitly denied every write, delete, retention, ACL and tagging
action on the bucket.

## Evidence writer assume policy

`trust-portal-evidence-writer-assume-policy.json` is for each producer of
evidence, a person or a non-human producer identity: `sts:AssumeRole` on the
evidence writer role and nothing else. Replace `ACCOUNT_ID` and
`EVIDENCE_WRITER_ROLE` with the role's account and name. A producer's own
identity holds this policy and uploads through an AWS CLI profile that
assumes the role from that identity's credentials, so the upload's
credentials are a one-hour session that can only add objects under the
store prefixes. The
writer role trusts only the IAM users and roles its stack names in
`EvidenceWriterPrincipalArns` (empty: nobody), and each of them also holds
this policy to assume it. The AWS deployment creates the same policy as a managed policy
(the core stack's `EvidenceWriterAssumePolicyArn` output), for attaching to
producer users and groups; `deploy/aws/tests/test_evidence_store.py` keeps
the two identical. Setup, step by step: `deploy/README.md` → "The evidence
store".
