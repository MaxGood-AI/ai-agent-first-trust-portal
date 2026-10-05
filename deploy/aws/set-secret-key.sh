#!/usr/bin/env bash
# Set one key of the portal's runtime secret from a file, without printing it.
#
#   bash deploy/aws/set-secret-key.sh --stack <stack-name> --key <KEY> --value-file <path> [--region <region>]
#
# Used for the operator-supplied keys, for example GITHUB_TOKEN for GitHub git
# sources. Every other key in the secret is kept. The file's trailing newline
# is dropped. The portal reads the secret when a container starts, so redeploy
# the current image afterwards (deploy/aws/deploy.sh).
set -euo pipefail
umask 077

STACK=""
KEY=""
VALUE_FILE=""
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"

usage() {
    echo "usage: $0 --stack <stack-name> --key <KEY> --value-file <path> [--region <region>]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --stack) STACK="${2:-}"; shift 2 ;;
        --key) KEY="${2:-}"; shift 2 ;;
        --value-file) VALUE_FILE="${2:-}"; shift 2 ;;
        --region) REGION="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$STACK" ] && [ -n "$KEY" ] && [ -n "$VALUE_FILE" ] && [ -n "$REGION" ] || usage
[[ "$KEY" =~ ^[A-Z][A-Z0-9_]*$ ]] || { echo "key must be UPPER_SNAKE_CASE" >&2; exit 2; }
case "$KEY" in
    DATABASE_OWNER_*|AUDIT_WITNESS_BUCKET|EVIDENCE_STORE_BUCKET)
        echo "$KEY never goes in the runtime secret: the owner credentials live in the owner" >&2
        echo "secret, and deploy.sh sets AUDIT_WITNESS_BUCKET per deployment (--no-witness)" >&2
        echo "and EVIDENCE_STORE_BUCKET from the core stack." >&2
        exit 2 ;;
esac
[ -s "$VALUE_FILE" ] || { echo "$VALUE_FILE is missing or empty" >&2; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

SECRET=$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='PortalSecretArn'].OutputValue | [0]" --output text)
aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET" \
    --query SecretString --output text > "$WORK/current.json"
jq --arg key "$KEY" --rawfile value "$VALUE_FILE" '.[$key] = ($value | rtrimstr("\n"))' \
    "$WORK/current.json" > "$WORK/next.json"
VERSION=$(aws secretsmanager put-secret-value --region "$REGION" --secret-id "$SECRET" \
    --secret-string "file://$WORK/next.json" --query VersionId --output text)
echo "$KEY set in $SECRET (version $VERSION). Redeploy the current image so the portal reads it."
