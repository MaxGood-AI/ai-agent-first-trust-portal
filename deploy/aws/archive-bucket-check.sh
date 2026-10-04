#!/usr/bin/env bash
# Prove the archive bucket's write rules against real S3, once per environment,
# before the first real archive (the unit tests' S3 mock does not evaluate
# bucket policies). Run it with the cutover operator's credentials (the core
# stack's ArchiveOperatorPolicyArn):
#
#   bash deploy/aws/archive-bucket-check.sh --stack <core-stack-name> [--region <region>]
#
# It writes under archives/deploy-test/<UTC timestamp>/ only: one small
# single-part object and one 5 MiB multipart object, both kept by Object Lock
# COMPLIANCE retention for ArchiveRetentionYears. It writes nothing under
# chain-heads/, where any non-head object would read as an invalid witness
# object for as long as it is retained. Each check prints PASS or FAIL; the
# script exits 1 on any FAIL.
set -euo pipefail
umask 077

STACK=""
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
while [ $# -gt 0 ]; do
    case "$1" in
        --stack) STACK="${2:-}"; shift 2 ;;
        --region) REGION="${2:-}"; shift 2 ;;
        *) echo "usage: $0 --stack <core-stack-name> [--region <region>]" >&2; exit 2 ;;
    esac
done
[ -n "$STACK" ] && [ -n "$REGION" ] || { echo "usage: $0 --stack <core-stack-name> [--region <region>]" >&2; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
BUCKET=$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='ArchiveBucketName'].OutputValue | [0]" --output text)
PREFIX="archives/deploy-test/$(date -u +%Y%m%dT%H%M%SZ)"
printf 'trust portal archive bucket check\n' > "$WORK/single.txt"
head -c 5242880 /dev/zero > "$WORK/part1"
printf 'x' > "$WORK/part2"
FAILED=0

# check <name> <expected: ok|412|denied> <command...>
check() {
    local name="$1" expected="$2" out got=ok
    shift 2
    if ! out=$("$@" 2>&1); then
        case "$out" in
            *PreconditionFailed*) got=412 ;;
            *AccessDenied*) got=denied ;;
            *) got=error ;;
        esac
    fi
    if [ "$got" = "$expected" ]; then
        echo "PASS  $name ($got)"
    else
        echo "FAIL  $name: expected $expected, got $got: ${out:0:300}"
        FAILED=1
    fi
}

put() {  # put <key> <extra args...>
    local key="$1"
    shift
    aws s3api put-object --region "$REGION" --bucket "$BUCKET" --key "$key" --body "$WORK/single.txt" \
        --checksum-algorithm SHA256 --query VersionId --output text "$@"
}

multipart() {  # multipart <key> <part files...>: a complete upload with If-None-Match
    local key="$1" upload number=0 part
    shift
    upload=$(aws s3api create-multipart-upload --region "$REGION" --bucket "$BUCKET" --key "$key" \
        --server-side-encryption AES256 --checksum-algorithm SHA256 --query UploadId --output text)
    echo '[]' > "$WORK/parts.json"
    for part in "$@"; do
        number=$((number + 1))
        aws s3api upload-part --region "$REGION" --bucket "$BUCKET" --key "$key" --upload-id "$upload" \
            --part-number "$number" --body "$part" --checksum-algorithm SHA256 \
            --query '{ETag: ETag, ChecksumSHA256: ChecksumSHA256}' --output json > "$WORK/part.json"
        jq --argjson n "$number" --slurpfile p "$WORK/part.json" '. + [$p[0] + {PartNumber: $n}]' \
            "$WORK/parts.json" > "$WORK/parts.next" && mv "$WORK/parts.next" "$WORK/parts.json"
    done
    jq '{Parts: .}' "$WORK/parts.json" > "$WORK/upload.json"
    if ! aws s3api complete-multipart-upload --region "$REGION" --bucket "$BUCKET" --key "$key" \
            --upload-id "$upload" --multipart-upload "file://$WORK/upload.json" --if-none-match '*' \
            --query VersionId --output text; then
        aws s3api abort-multipart-upload --region "$REGION" --bucket "$BUCKET" --key "$key" \
            --upload-id "$upload" > /dev/null 2>&1 || true
        return 1
    fi
}

echo "Bucket $BUCKET, test prefix $PREFIX"
check "single-part write with If-None-Match and SSE-S3" ok put "$PREFIX/single.txt" --if-none-match '*' --server-side-encryption AES256
check "the same key again is refused" 412 put "$PREFIX/single.txt" --if-none-match '*' --server-side-encryption AES256
check "a write without If-None-Match is denied" denied put "$PREFIX/unconditional.txt" --server-side-encryption AES256
check "a write with SSE-KMS is denied" denied put "$PREFIX/kms.txt" --if-none-match '*' --server-side-encryption aws:kms
check "multipart upload (SSE-S3, SHA-256 parts) completes with If-None-Match" ok multipart "$PREFIX/multipart.bin" "$WORK/part1" "$WORK/part2"
check "a second multipart upload to the same key is refused" 412 multipart "$PREFIX/multipart.bin" "$WORK/part2"
echo "Test objects under $PREFIX/ stay under Object Lock COMPLIANCE retention; they cannot be deleted."
exit "$FAILED"
