#!/usr/bin/env bash
# Prove the evidence store bucket's rules against real S3, once per
# environment, after the core stack update that creates the bucket (the unit
# tests' S3 mock evaluates neither bucket policies nor Object Lock). Run it
# with an operator's own credentials whose IAM policy allows S3 on the bucket
# (an account administrator), so that every refusal it reports comes from the
# bucket itself:
#
#   bash deploy/aws/evidence-bucket-check.sh --stack <core-stack-name> [--region <region>] \
#       [--writer-profile <AWS CLI profile>]
#
# It needs the AWS CLI, openssl and python3. It writes only under
# bucket-check/<UTC timestamp>/, outside the store's key prefixes, so the
# portal never imports what it leaves there: two small objects that Object
# Lock keeps for EvidenceRetentionYears, and one multipart upload that it
# aborts. Its one put under a store prefix, which the bucket refuses to every
# principal but the stack's EvidenceWriterRole, names
# decision-logs/bucket-check/<UTC timestamp>/operator.txt, a key the portal
# records as unmapped; its FAIL line names that key. It checks that that put,
# a put without If-None-Match, a second put to a stored
# key (412), an SSE-C, SSE-KMS or non-STANDARD put, a put carrying Object Lock
# retention or legal-hold headers, a multipart upload completed without
# If-None-Match, a copy into the bucket, every delete (with and without
# --bypass-governance-retention) and every retention or legal-hold change are
# refused; that a put with If-None-Match and --checksum-sha256 is stored with
# that checksum under the bucket's GOVERNANCE default retention, retained for
# EvidenceRetentionYears from its creation; and that versioning, the Object
# Lock default (mode and exact period), default encryption, the public access
# block, the bucket policy's denials and the lifecycle rules are as
# configured. With --writer-profile, the AWS CLI profile a producer uploads
# with (one that assumes the stack's EvidenceWriterRoleArn), it then checks
# that the profile acts as that role and that the role is refused the
# requests a producer never makes: reading, listing and listing versions,
# deleting the object or its version, a put outside the store prefixes, and
# retention, legal-hold, ACL and tagging changes (it writes nothing under the
# store prefixes, so it proves only the refusals). It reads no credential and
# prints none. Each check prints PASS or FAIL; the script exits 1 on any FAIL.
set -euo pipefail
umask 077

STACK=""
WRITER=""
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
usage() { echo "usage: $0 --stack <core-stack-name> [--region <region>] [--writer-profile <profile>]" >&2; exit 2; }
while [ $# -gt 0 ]; do
    case "$1" in
        --stack) STACK="${2:-}"; shift 2 ;;
        --region) REGION="${2:-}"; shift 2 ;;
        --writer-profile) [ -n "${2:-}" ] || usage; WRITER="$2"; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$STACK" ] && [ -n "$REGION" ] || usage

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
stack() {  # stack <JMESPath under Stacks[0]>
    aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" --query "Stacks[0].$1" --output text
}
BUCKET=$(stack "Outputs[?OutputKey=='EvidenceBucketName'].OutputValue | [0]")
YEARS=$(stack "Parameters[?ParameterKey=='EvidenceRetentionYears'].ParameterValue | [0]")
ERASER=$(stack "Parameters[?ParameterKey=='EvidenceErasurePrincipalArn'].ParameterValue | [0]")
[ -n "$BUCKET" ] && [ "$BUCKET" != "None" ] || { echo "stack $STACK has no EvidenceBucketName output" >&2; exit 1; }
[[ "$YEARS" =~ ^[0-9]+$ ]] || { echo "stack $STACK has no EvidenceRetentionYears parameter" >&2; exit 1; }
[ "$ERASER" != "None" ] || ERASER=""
WRITER_ROLE=$(stack "Outputs[?OutputKey=='EvidenceWriterRoleArn'].OutputValue | [0]")
[[ "$WRITER_ROLE" =~ ^arn:[a-z-]+:iam::[0-9]{12}:role/[^/]+$ ]] \
    || { echo "stack $STACK has no EvidenceWriterRoleArn output" >&2; exit 1; }

PREFIX="bucket-check/$(date -u +%Y%m%dT%H%M%SZ)"
KEY="$PREFIX/object.txt"
UPLOAD_KEY="$PREFIX/multipart.txt"
STORE_KEY="decision-logs/$PREFIX/operator.txt"  # under a store prefix; the portal records it as unmapped
printf 'trust portal evidence bucket check %s\n' "$PREFIX" > "$WORK/body.txt"
SHA=$(openssl dgst -sha256 -binary "$WORK/body.txt" | base64)
SSE_C_KEY=$(head -c 24 /dev/urandom | base64)  # 32 bytes, a throwaway key for a put that must be refused
NEXT_YEAR="$(( $(date -u +%Y) + 1 ))-01-01T00:00:00Z"  # a retention of its own, shorter than the default
FAILED=0
OUT=""

record() {  # record <name> <expected> <got> [detail shown on FAIL]
    if [ "$3" = "$2" ]; then
        echo "PASS  $1 ($3)"
    else
        echo "FAIL  $1: expected $2, got $3${4:+: ${4:0:300}}"
        FAILED=1
    fi
}

# check <name> <expected: ok|412|denied> <command...>; the command's output is left in OUT. A
# profile that fails to assume its role is an error, never a refusal of the request itself.
check() {
    local name="$1" expected="$2" got=ok
    shift 2
    if ! OUT=$("$@" 2> "$WORK/err"); then
        case "$(cat "$WORK/err")" in
            *"AssumeRole operation"*) got=error ;;
            *PreconditionFailed*) got=412 ;;
            *AccessDenied*) got=denied ;;
            *) got=error ;;
        esac
    fi
    record "$name" "$expected" "$got" "$(tr '\n' ' ' < "$WORK/err")"
}

# expect <name> <expected text> <command...>: the command's text output, tabs as spaces
expect() {
    local name="$1" expected="$2" got
    shift 2
    if got=$("$@" 2> "$WORK/err"); then
        record "$name" "$expected" "$(printf '%s' "$got" | tr '\t' ' ')"
    else
        record "$name" "$expected" error "$(tr '\n' ' ' < "$WORK/err")"
    fi
}

s3() {  # s3 <s3api operation> <args...> on the evidence bucket
    local operation="$1"
    shift
    aws s3api "$operation" --region "$REGION" --bucket "$BUCKET" "$@"
}

put() {  # put <key> <args...>: one PutObject carrying the body's SHA-256
    local key="$1"
    shift
    s3 put-object --key "$key" --body "$WORK/body.txt" --checksum-sha256 "$SHA" \
        --query '[VersionId, ChecksumSHA256]' --output text "$@"
}

# start_upload <key>: CreateMultipartUpload and one UploadPart (neither creates an object, so
# neither needs If-None-Match); leaves the upload id and the completion input in $WORK
start_upload() {
    s3 create-multipart-upload --key "$1" --checksum-algorithm SHA256 --query UploadId --output text \
        > "$WORK/upload-id" &&
        s3 upload-part --key "$1" --upload-id "$(cat "$WORK/upload-id")" --part-number 1 --body "$WORK/body.txt" \
            --checksum-sha256 "$SHA" --output json \
            --query '{Parts: [{PartNumber: `1`, ETag: ETag, ChecksumSHA256: ChecksumSHA256}]}' > "$WORK/upload.json"
}

days() {  # days <ISO 8601 date or timestamp>: the days from 1970-01-01 to its date
    [[ "$1" =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2}) ]] || return 1
    local y=$((10#${BASH_REMATCH[1]})) m=$((10#${BASH_REMATCH[2]})) d=$((10#${BASH_REMATCH[3]})) era yoe doy
    if [ "$m" -le 2 ]; then y=$((y - 1)); fi
    era=$((y / 400))
    yoe=$((y - era * 400))
    doy=$(((153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1))
    echo $((era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468))
}

# retention_period <created> <retain-until>: "<YEARS> years" when the retain-until date lies
# EvidenceRetentionYears after the creation date (365 days a year, or calendar years), else the days
retention_period() {
    local created retained
    created=$(days "$1") && retained=$(days "$2") || { echo "unknown (created ${1:-none}, retained until ${2:-none})"; return; }
    if [ $((retained - created)) -ge $((YEARS * 365)) ] && [ $((retained - created)) -le $((YEARS * 365 + (YEARS + 3) / 4)) ]; then
        echo "$YEARS years"
    else
        echo "$((retained - created)) days"
    fi
}

# policy_rules denials|allows: the Sids of the bucket policy's statements that hold the store's
# denials exactly (a Deny to every principal on the bucket's objects, or on each store prefix,
# with these actions and conditions), or the number of statements that are not a Deny
policy_rules() {
    python3 - "$1" "$WORK/policy.json" "arn:aws:s3:::$BUCKET/*" "$ERASER" "$WRITER_ROLE" <<'PY'
import json, sys

mode, path, objects, eraser, writer = sys.argv[1:]
store = [objects[:-1] + prefix + "*" for prefix in
         ("decision-logs/", "codex-reviews/", "pentest-evidence/", "pentest-reports/", "evidence/artifacts/")]
with open(path) as handle:
    statements = json.load(handle)["Statement"]
statements = statements if isinstance(statements, list) else [statements]


def norm(value):
    """Compare policies as IAM reads them: one-element lists as values, scalars as strings."""
    if isinstance(value, dict):
        return {key: norm(item) for key, item in value.items()}
    if isinstance(value, list):
        items = sorted((norm(item) for item in value), key=json.dumps)
        return items[0] if len(items) == 1 else items
    if isinstance(value, bool):
        return str(value).lower()
    return str(value) if isinstance(value, (int, float)) else value


def actions(value):
    return norm([action.lower() for action in (value if isinstance(value, list) else [value])])


RULES = {
    "DenyInsecureTransport": ("s3:*", {"Bool": {"aws:SecureTransport": "false"}}),
    "DenyWriteWithoutIfNoneMatch": ("s3:PutObject", {"Null": {"s3:if-none-match": "true"},
                                                     "Bool": {"s3:ObjectCreationOperation": "true"}}),
    "DenyNonSseS3Writes": ("s3:PutObject", {"Null": {"s3:x-amz-server-side-encryption": "false"},
                                            "StringNotEquals": {"s3:x-amz-server-side-encryption": "AES256"}}),
    "DenySseCWrites": ("s3:PutObject", {"Null": {"s3:x-amz-server-side-encryption-customer-algorithm": "false"}}),
    "DenyNonStandardStorageClass": ("s3:PutObject", {"Null": {"s3:x-amz-storage-class": "false"},
                                                     "StringNotEquals": {"s3:x-amz-storage-class": "STANDARD"}}),
    "OnlyTheWriterRoleWritesEvidence": ("s3:PutObject", {"ArnNotEquals": {"aws:PrincipalArn": writer}}, store),
    "DenyReplicationWrites": (["s3:ReplicateObject", "s3:ReplicateDelete"], None),
    "DenyDeletesAndRetentionChanges": (
        ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
         "s3:BypassGovernanceRetention"],
        {"ArnNotEquals": {"aws:PrincipalArn": eraser}} if eraser else None),
}

if mode == "allows":
    print(sum(1 for statement in statements if statement.get("Effect") != "Deny"))
    sys.exit(0)
held = set()
for statement in statements:
    rule = RULES.get(statement.get("Sid"))
    resources = statement.get("Resource", [])
    resources = resources if isinstance(resources, list) else [resources]
    if (rule and statement.get("Effect") == "Deny" and norm(statement.get("Principal")) in ("*", {"AWS": "*"})
            and all(resource in resources for resource in (rule[2] if len(rule) > 2 else [objects]))
            and actions(statement.get("Action", [])) == actions(rule[0])
            and norm(statement.get("Condition")) == norm(rule[1])):
        held.add(statement["Sid"])
print(" ".join(sorted(held)))
PY
}

echo "Bucket $BUCKET, test prefix $PREFIX/"
check "a put without If-None-Match is refused" denied put "$PREFIX/unconditional.txt"
check "a put with If-None-Match and --checksum-sha256 is stored" ok put "$KEY" --if-none-match '*'
read -r VERSION STORED <<< "$OUT"
VERSION="${VERSION:-none}"
record "the put returned the SHA-256 checksum it sent" "$SHA" "${STORED:-none}"
check "a second put to the same key is refused" 412 put "$KEY" --if-none-match '*'
check "a put with explicit SSE-S3 and STANDARD is stored" ok \
    put "$PREFIX/explicit.txt" --if-none-match '*' --server-side-encryption AES256 --storage-class STANDARD
check "the operator's put to $STORE_KEY (a store prefix) is refused" denied \
    put "$STORE_KEY" --if-none-match '*'
[ -z "$OUT" ] || echo "      $STORE_KEY is stored: Object Lock keeps it, and the portal records it as unmapped"
check "an SSE-C put is refused" denied \
    put "$PREFIX/sse-c.txt" --if-none-match '*' --sse-customer-algorithm AES256 --sse-customer-key "$SSE_C_KEY"
check "an SSE-KMS put is refused" denied put "$PREFIX/sse-kms.txt" --if-none-match '*' --server-side-encryption aws:kms
check "a STANDARD_IA put is refused" denied put "$PREFIX/standard-ia.txt" --if-none-match '*' --storage-class STANDARD_IA
check "a put with an Object Lock retention of its own is refused" denied put "$PREFIX/retention.txt" --if-none-match '*' \
    --object-lock-mode GOVERNANCE --object-lock-retain-until-date "$NEXT_YEAR"
check "a put with a legal hold is refused" denied put "$PREFIX/legal-hold.txt" --if-none-match '*' \
    --object-lock-legal-hold-status ON
check "a multipart upload starts (CreateMultipartUpload, UploadPart)" ok start_upload "$UPLOAD_KEY"
UPLOAD_ID=$(cat "$WORK/upload-id" 2> /dev/null || true)
check "completing a multipart upload without If-None-Match is refused" denied s3 complete-multipart-upload \
    --key "$UPLOAD_KEY" --upload-id "${UPLOAD_ID:-none}" --multipart-upload "file://$WORK/upload.json"
check "the refused multipart upload is aborted" ok s3 abort-multipart-upload --key "$UPLOAD_KEY" --upload-id "${UPLOAD_ID:-none}"
check "a copy into the bucket (CopyObject without If-None-Match) is refused" denied \
    s3 copy-object --key "$PREFIX/copy.txt" --copy-source "$BUCKET/$KEY?versionId=$VERSION" --query VersionId --output text
check "a delete (a delete marker) is refused" denied s3 delete-object --key "$KEY"
check "deleting the version is refused" denied s3 delete-object --key "$KEY" --version-id "$VERSION"
check "deleting the version with --bypass-governance-retention is refused" denied \
    s3 delete-object --key "$KEY" --version-id "$VERSION" --bypass-governance-retention

check "the stored version is readable" ok s3 head-object --key "$KEY" --version-id "$VERSION" --checksum-mode ENABLED \
    --query '[ObjectLockMode, ChecksumSHA256, ServerSideEncryption, ObjectLockRetainUntilDate]' --output text
read -r MODE HEAD_SHA SSE RETAIN <<< "$OUT"
CREATED=$(s3 list-object-versions --prefix "$KEY" --query 'Versions[0].LastModified' --output text 2> /dev/null || true)
record "the version carries the GOVERNANCE default retention" GOVERNANCE "${MODE:-none}"
record "the version keeps the SHA-256 checksum sent" "$SHA" "${HEAD_SHA:-none}"
record "the version is encrypted with SSE-S3" AES256 "${SSE:-none}"
record "the version is retained for $YEARS years from its creation" "$YEARS years" "$(retention_period "${CREATED:-}" "${RETAIN:-}")"
RETAIN_YEAR="${RETAIN:0:4}"
[[ "$RETAIN_YEAR" =~ ^[0-9]{4}$ ]] || RETAIN_YEAR=2100
EXTENDED="$((RETAIN_YEAR + 1))-01-01T00:00:00Z"
check "extending the version's retention is refused" denied s3 put-object-retention --key "$KEY" --version-id "$VERSION" \
    --retention "{\"Mode\":\"GOVERNANCE\",\"RetainUntilDate\":\"$EXTENDED\"}"
check "a legal hold on the version is refused" denied s3 put-object-legal-hold --key "$KEY" --version-id "$VERSION" \
    --legal-hold '{"Status":"ON"}'
expect "the key holds one version and no delete marker" "1 0" s3 list-object-versions --prefix "$KEY" \
    --query '[length(Versions || `[]`), length(DeleteMarkers || `[]`)]' --output text

expect "versioning is enabled" Enabled s3 get-bucket-versioning --query Status --output text
expect "Object Lock defaults to GOVERNANCE for exactly $YEARS years" "Enabled GOVERNANCE $YEARS None" \
    s3 get-object-lock-configuration --output text --query '[ObjectLockConfiguration.ObjectLockEnabled, ObjectLockConfiguration.Rule.DefaultRetention.Mode, ObjectLockConfiguration.Rule.DefaultRetention.Years, ObjectLockConfiguration.Rule.DefaultRetention.Days]'
expect "default encryption is SSE-S3" AES256 s3 get-bucket-encryption \
    --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text
expect "every form of public access is blocked" "True True True True" s3 get-public-access-block \
    --query '[PublicAccessBlockConfiguration.BlockPublicAcls, PublicAccessBlockConfiguration.IgnorePublicAcls, PublicAccessBlockConfiguration.BlockPublicPolicy, PublicAccessBlockConfiguration.RestrictPublicBuckets]' \
    --output text
check "the bucket policy exists" ok s3 get-bucket-policy --query Policy --output text
printf '%s\n' "$OUT" > "$WORK/policy.json"
expect "the bucket policy holds the store's denials" \
    "DenyDeletesAndRetentionChanges DenyInsecureTransport DenyNonSseS3Writes DenyNonStandardStorageClass DenyReplicationWrites DenySseCWrites DenyWriteWithoutIfNoneMatch OnlyTheWriterRoleWritesEvidence" \
    policy_rules denials
expect "the bucket policy allows nothing" 0 policy_rules allows
expect "the one lifecycle rule aborts incomplete uploads after 1 day and expires nothing" "1 0 1" \
    s3 get-bucket-lifecycle-configuration --output text --query '[length(Rules), length(Rules[?Expiration || Transitions || NoncurrentVersionExpiration || NoncurrentVersionTransitions]), Rules[0].AbortIncompleteMultipartUpload.DaysAfterInitiation]'

# The writer profile: it acts as the writer role (session name aside), and the role is refused
# each request a producer never makes. Its targets are this run's own objects.
refused() {  # refused <what> <command...>: the command, sent with the writer profile, is refused
    local what="$1"
    shift
    check "the writer role cannot $what" denied "$@" --profile "$WRITER"
}
if [ -n "$WRITER" ]; then
    echo "Writer profile $WRITER, role $WRITER_ROLE"
    ASSUMED="${WRITER_ROLE/:iam::/:sts::}"
    ASSUMED="${ASSUMED/:role\//:assumed-role/}"
    CALLER=$(aws sts get-caller-identity --profile "$WRITER" --query Arn --output text 2> "$WORK/err" || echo error)
    record "the writer profile acts as the evidence writer role" "$ASSUMED" "${CALLER%/*}" "$(tr '\n' ' ' < "$WORK/err")"
    refused "read the stored version (GetObject)" s3 get-object --key "$KEY" --version-id "$VERSION" "$WORK/read.txt"
    refused "list the bucket (ListBucket)" s3 list-objects-v2 --prefix "$PREFIX/" --max-items 1 --query KeyCount --output text
    refused "list object versions (ListBucketVersions)" s3 list-object-versions --prefix "$KEY" --max-items 1 \
        --query 'length(Versions || `[]`)' --output text
    refused "delete the object (DeleteObject)" s3 delete-object --key "$KEY"
    refused "delete the version (DeleteObjectVersion)" s3 delete-object --key "$KEY" --version-id "$VERSION"
    refused "put outside the store prefixes (PutObject)" put "$PREFIX/writer.txt" --if-none-match '*'
    refused "change the version's retention (PutObjectRetention)" s3 put-object-retention --key "$KEY" \
        --version-id "$VERSION" --retention "{\"Mode\":\"GOVERNANCE\",\"RetainUntilDate\":\"$EXTENDED\"}"
    refused "place a legal hold on the version (PutObjectLegalHold)" s3 put-object-legal-hold --key "$KEY" \
        --version-id "$VERSION" --legal-hold '{"Status":"ON"}'
    refused "set the version's ACL (PutObjectAcl)" s3 put-object-acl --key "$KEY" --version-id "$VERSION" \
        --acl bucket-owner-full-control
    refused "tag the version (PutObjectTagging)" s3 put-object-tagging --key "$KEY" --version-id "$VERSION" \
        --tagging '{"TagSet":[{"Key":"bucket-check","Value":"writer"}]}'
fi
echo "Objects under $PREFIX/ stay under Object Lock GOVERNANCE retention; the portal never imports them."
exit "$FAILED"
