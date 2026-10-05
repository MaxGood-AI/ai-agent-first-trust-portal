#!/usr/bin/env bash
# Deploy one container image to the trust portal's Lightsail container service.
#
#   bash deploy/aws/deploy.sh --stack <core-stack-name> --image <image-uri> (--witness | --no-witness) [--region <region>]
#
# Every name comes from the outputs of the core CloudFormation stack built from
# deploy/aws/trust-portal.yaml. Every run states its witness mode; nothing is
# carried over from an earlier run. --witness gives the container
# AUDIT_WITNESS_BUCKET (the archive bucket), so the portal publishes its audit
# chain heads there once the witness is armed (audit-anchor --manifest at
# cutover, or cli audit-witness-arm). --no-witness sets AUDIT_WITNESS_DISABLED=true
# (the portal's kill switch, read from the environment only) and leaves
# AUDIT_WITNESS_BUCKET unset, so nothing is published: use it for a database
# whose chain will be discarded (an empty-database shakedown), whose heads
# would later read as a replaced audit log. After the deployment /api/health
# must report "witness": "disabled" with --no-witness, and "enabled" or
# "unarmed" with --witness. The script:
#   1. takes a snapshot of the database, named <SnapshotPrefix><UTC timestamp>
#      so the daily snapshot function prunes it with the same retention, and
#      waits until it is available (migrations run at container start);
#   2. creates a container-service deployment with the container environment
#      the portal needs (base access key, runtime role, secret id, database,
#      EVIDENCE_STORE_BUCKET (the evidence store bucket, on every run), and the
#      database owner credentials, which the entrypoint uses for migrations and
#      removes before the server starts);
#   3. waits until Lightsail reports that deployment ACTIVE, then checks
#      <PublicUrl><HealthCheckPath> answers 200.
# A deployment that never becomes healthy ends FAILED, the previous deployment
# keeps serving, and the script exits non-zero. Lightsail allows a new
# container 300 s of failing health checks (10 checks, 30 s apart) before it
# fails the deployment; the entrypoint needs at most 120 s to reach the
# database, 37 s per blocked migration step (5 attempts with a 5 s lock
# timeout, 3 s apart), then the migrations themselves and the server start.
#
# Needs the AWS CLI, jq and curl. The base access key and the owner
# credentials are read from Secrets Manager into private temporary files and
# are never printed: every AWS call whose response would echo the container
# environment is filtered by --query.
set -euo pipefail
umask 077

STACK=""
IMAGE=""
WITNESS=""
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
POLL_SECONDS="${POLL_SECONDS:-20}"
SNAPSHOT_TIMEOUT_SECONDS="${SNAPSHOT_TIMEOUT_SECONDS:-3600}"
DEPLOY_TIMEOUT_SECONDS="${DEPLOY_TIMEOUT_SECONDS:-1800}"
CONTAINER_NAME="portal"

usage() {
    echo "usage: $0 --stack <core-stack-name> --image <image-uri> (--witness | --no-witness) [--region <region>]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --stack) STACK="${2:-}"; shift 2 ;;
        --image) IMAGE="${2:-}"; shift 2 ;;
        --region) REGION="${2:-}"; shift 2 ;;
        --witness) [ -z "$WITNESS" ] || usage; WITNESS=1; shift ;;
        --no-witness) [ -z "$WITNESS" ] || usage; WITNESS=0; shift ;;
        *) usage ;;
    esac
done
[ -n "$STACK" ] && [ -n "$IMAGE" ] && [ -n "$REGION" ] && [ -n "$WITNESS" ] || usage

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "FAILED: $*"; exit 1; }

aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" \
    --query 'Stacks[0].Outputs' --output json > "$WORK/outputs.json"
output() {
    local value
    value=$(jq -r --arg key "$1" '.[] | select(.OutputKey == $key) | .OutputValue' "$WORK/outputs.json")
    [ -n "$value" ] || fail "stack $STACK has no output $1"
    printf '%s' "$value"
}

SERVICE=$(output ContainerServiceName)
DATABASE_RESOURCE=$(output DatabaseResourceName)
SNAPSHOT_PREFIX=$(output SnapshotPrefix)
SNAPSHOT_TAG_VALUE=$(output SnapshotTagValue)
CREDENTIALS_SECRET=$(output CredentialsSecretArn)
OWNER_SECRET=$(output OwnerSecretArn)
PORT=$(output ContainerPort)
HEALTH_PATH=$(output HealthCheckPath)
PUBLIC_URL=$(output PublicUrl)
RUNTIME_ROLE_ARN=$(output RuntimeRoleArn)
RUNTIME_ROLE_EXTERNAL_ID=$(output RuntimeRoleExternalId)
PORTAL_SECRET_ARN=$(output PortalSecretArn)
DATABASE_NAME=$(output DatabaseName)
DATABASE_USER=$(output DatabaseUser)
EVIDENCE_BUCKET=$(output EvidenceBucketName)
WITNESS_BUCKET=""
if [ "$WITNESS" -eq 1 ]; then
    WITNESS_BUCKET=$(output ArchiveBucketName)
fi

log "Deploying $IMAGE to $SERVICE"
if [ -n "$WITNESS_BUCKET" ]; then
    log "Audit chain heads: s3://$WITNESS_BUCKET/chain-heads/ (--witness; published once the witness is armed)"
else
    log "Audit chain heads: NOT published by this deployment (--no-witness: AUDIT_WITNESS_DISABLED=true)"
fi
log "Evidence store: s3://$EVIDENCE_BUCKET/ (EVIDENCE_STORE_BUCKET, read-only through the runtime role)"

# --- Database endpoint -------------------------------------------------------
read -r DB_STATE DB_HOST DB_PORT < <(aws lightsail get-relational-database --region "$REGION" \
    --relational-database-name "$DATABASE_RESOURCE" \
    --query 'relationalDatabase.[state, masterEndpoint.address, masterEndpoint.port]' --output text)
[ "$DB_STATE" = "available" ] || fail "database $DATABASE_RESOURCE is $DB_STATE, not available"

# --- Pre-deployment snapshot -------------------------------------------------
# The stack tag is what lets the deploy role create, and the snapshot function
# later prune, this snapshot; both roles are denied untagged snapshots.
SNAPSHOT="${SNAPSHOT_PREFIX}$(date -u +%Y%m%d-%H%M%S)"
SNAPSHOT_TAGS=$(jq -cn --arg value "$SNAPSHOT_TAG_VALUE" '[{key: "trust-portal-stack", value: $value}]')
aws lightsail create-relational-database-snapshot --region "$REGION" \
    --relational-database-name "$DATABASE_RESOURCE" \
    --relational-database-snapshot-name "$SNAPSHOT" \
    --tags "$SNAPSHOT_TAGS" \
    --query 'operations[0].status' --output text > /dev/null
log "Snapshot $SNAPSHOT requested"
waited=0
while :; do
    state=$(aws lightsail get-relational-database-snapshot --region "$REGION" \
        --relational-database-snapshot-name "$SNAPSHOT" \
        --query 'relationalDatabaseSnapshot.state' --output text 2>/dev/null || echo pending)
    log "Snapshot $SNAPSHOT: $state"
    [ "$state" = "available" ] && break
    [ "$waited" -ge "$SNAPSHOT_TIMEOUT_SECONDS" ] && fail "snapshot $SNAPSHOT not available after ${waited}s"
    sleep "$POLL_SECONDS"
    waited=$((waited + POLL_SECONDS))
done

# --- Deployment --------------------------------------------------------------
aws secretsmanager get-secret-value --region "$REGION" --secret-id "$CREDENTIALS_SECRET" \
    --query SecretString --output text > "$WORK/credentials.json"
aws secretsmanager get-secret-value --region "$REGION" --secret-id "$OWNER_SECRET" \
    --query SecretString --output text > "$WORK/owner.json"

# The owner credentials reach only the entrypoint, which runs migrations and
# role provisioning with them and removes them before the server starts.
jq -n \
    --slurpfile credentials "$WORK/credentials.json" \
    --slurpfile owner "$WORK/owner.json" \
    --arg name "$CONTAINER_NAME" \
    --arg image "$IMAGE" \
    --arg port "$PORT" \
    --arg region "$REGION" \
    --arg role "$RUNTIME_ROLE_ARN" \
    --arg external_id "$RUNTIME_ROLE_EXTERNAL_ID" \
    --arg secret_id "$PORTAL_SECRET_ARN" \
    --arg db_host "$DB_HOST" \
    --arg db_port "$DB_PORT" \
    --arg db_name "$DATABASE_NAME" \
    --arg db_user "$DATABASE_USER" \
    --arg witness "$WITNESS_BUCKET" \
    --arg evidence "$EVIDENCE_BUCKET" \
    '{($name): {
        image: $image,
        ports: {($port): "HTTP"},
        environment: ((if $witness == "" then {AUDIT_WITNESS_DISABLED: "true"} else {AUDIT_WITNESS_BUCKET: $witness} end) + {
            PORTAL_ENV: "production",
            EVIDENCE_STORE_BUCKET: $evidence,
            AWS_REGION: $region,
            AWS_ACCESS_KEY_ID: $credentials[0].AWS_ACCESS_KEY_ID,
            AWS_SECRET_ACCESS_KEY: $credentials[0].AWS_SECRET_ACCESS_KEY,
            AWS_RUNTIME_ROLE_ARN: $role,
            AWS_RUNTIME_ROLE_EXTERNAL_ID: $external_id,
            PORTAL_SECRET_ID: $secret_id,
            DATABASE_HOST: $db_host,
            DATABASE_PORT: $db_port,
            DATABASE_NAME: $db_name,
            DATABASE_USER: $db_user,
            DATABASE_OWNER_USER: $owner[0].DATABASE_OWNER_USER,
            DATABASE_OWNER_PASSWORD: $owner[0].DATABASE_OWNER_PASSWORD
        })
    }}' > "$WORK/containers.json"
rm -f "$WORK/credentials.json" "$WORK/owner.json"

jq -n --arg name "$CONTAINER_NAME" --arg port "$PORT" --arg path "$HEALTH_PATH" \
    '{containerName: $name, containerPort: ($port | tonumber),
      healthCheck: {path: $path, successCodes: "200", intervalSeconds: 30,
                    timeoutSeconds: 5, healthyThreshold: 2, unhealthyThreshold: 10}}' \
    > "$WORK/endpoint.json"

VERSION=$(aws lightsail create-container-service-deployment --region "$REGION" \
    --service-name "$SERVICE" \
    --containers "file://$WORK/containers.json" \
    --public-endpoint "file://$WORK/endpoint.json" \
    --query 'containerService.nextDeployment.version' --output text)
rm -f "$WORK/containers.json"
log "Deployment version $VERSION created"

waited=0
while :; do
    state=$(aws lightsail get-container-service-deployments --region "$REGION" \
        --service-name "$SERVICE" \
        --query "deployments[?version==\`$VERSION\`].state | [0]" --output text)
    log "Deployment $VERSION: $state"
    case "$state" in
        ACTIVE) break ;;
        FAILED) fail "deployment $VERSION failed its health checks; the previous deployment keeps serving" ;;
    esac
    [ "$waited" -ge "$DEPLOY_TIMEOUT_SECONDS" ] && fail "deployment $VERSION not active after ${waited}s"
    sleep "$POLL_SECONDS"
    waited=$((waited + POLL_SECONDS))
done

HEALTH_URL="${PUBLIC_URL%/}${HEALTH_PATH}"
code=$(curl -sS -o "$WORK/health.json" -w '%{http_code}' --max-time 15 "$HEALTH_URL" || true)
[ "$code" = "200" ] || fail "$HEALTH_URL answered $code"
log "Healthy: $HEALTH_URL $(cat "$WORK/health.json")"
ACTUAL_WITNESS=$(jq -r '.witness // "missing"' "$WORK/health.json" 2>/dev/null || echo unreadable)
LAST_PUBLISHED=$(jq -r '.last_published_at // "never"' "$WORK/health.json" 2>/dev/null || echo unreadable)
STALE=$(jq -r '.witness_stale // false' "$WORK/health.json" 2>/dev/null || echo unknown)
if [ "$WITNESS" -eq 1 ]; then
    case "$ACTUAL_WITNESS" in
        enabled) log "Witness: enabled (last head published $LAST_PUBLISHED, stale: $STALE)" ;;
        unarmed) log "Witness: unarmed - configured, publishing once armed (audit-anchor --manifest or cli audit-witness-arm)" ;;
        *) fail "the portal reports witness \"$ACTUAL_WITNESS\"; --witness expects \"enabled\" or \"unarmed\"" ;;
    esac
else
    [ "$ACTUAL_WITNESS" = "disabled" ] \
        || fail "the portal reports witness \"$ACTUAL_WITNESS\"; --no-witness expects \"disabled\""
    log "Witness: disabled, as intended"
fi
