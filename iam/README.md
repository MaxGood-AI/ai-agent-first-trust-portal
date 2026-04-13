# Trust Portal — AWS IAM Assets

This directory holds the canonical IAM documents for deploying the
`ai-agent-first-trust-portal` on AWS. These files are the single source of
truth for the permissions the portal's evidence collectors need — the
portal's onboarding wizard reads them at runtime to display exactly what
an admin must grant.

## Files

| File | Purpose |
|---|---|
| `trust-portal-collector-policy.json` | Read-only IAM permissions policy for the collector role. Attached to `trust-portal-collector-role`. |
| `trust-portal-task-role-trust-policy.json` | Trust policy for the ECS task role. Allows `ecs-tasks.amazonaws.com` to assume it. |
| `trust-portal-collector-role-trust-policy.json` | Trust policy for the collector role. Allows the task role to assume it. Replace `ACCOUNT_ID` with your actual AWS account ID. |
| `terraform/` | Terraform module that provisions both roles and attaches the policy. See `terraform/README.md`. |

## Architecture — two-role pattern

```
ECS Fargate task  ────(assumes)───▶  trust-portal-collector-role
     │                                          │
     │                                          │ read-only scan perms
     ▼                                          ▼
trust-portal-task-role           IAM / RDS / S3 / EC2 / ELB / ACM /
     │                            ElastiCache / ECS / KMS / CloudTrail /
     │ minimum perms              CloudWatch Logs / STS
     ▼
 Secrets Manager (portal secrets)
 CloudWatch Logs (self-logging)
 sts:AssumeRole → collector-role
```

- **`trust-portal-task-role`** is attached to the ECS task. It has only
  the permissions the portal container itself needs to operate: reading
  its own secrets from Secrets Manager, writing its own logs, and
  assuming the collector role.
- **`trust-portal-collector-role`** contains all read-only scan
  permissions. The task role assumes it at collection time via STS.

This isolates collector permissions from portal operation. A bug in the
portal's request-handling code cannot exercise collector permissions
except during an explicit `AssumeRole` call, which shows up cleanly in
CloudTrail.

## Deploying with Terraform (recommended)

See [`terraform/README.md`](terraform/README.md) for a drop-in module.

## Deploying manually (AWS CLI)

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Task role
aws iam create-role \
  --role-name trust-portal-task-role \
  --assume-role-policy-document file://trust-portal-task-role-trust-policy.json

# Collector role — first substitute the account ID into the trust policy
sed "s/ACCOUNT_ID/${ACCOUNT_ID}/" trust-portal-collector-role-trust-policy.json \
  > /tmp/collector-trust.json
aws iam create-role \
  --role-name trust-portal-collector-role \
  --assume-role-policy-document file:///tmp/collector-trust.json

# Attach the read-only policy to the collector role
aws iam put-role-policy \
  --role-name trust-portal-collector-role \
  --policy-name trust-portal-collector-read-only \
  --policy-document file://trust-portal-collector-policy.json

# Allow the task role to assume the collector role
cat > /tmp/task-assume.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": "arn:aws:iam::${ACCOUNT_ID}:role/trust-portal-collector-role"
  }]
}
EOF
aws iam put-role-policy \
  --role-name trust-portal-task-role \
  --policy-name trust-portal-task-assume-collector \
  --policy-document file:///tmp/task-assume.json
```

## What the permissions cover

Each SID in `trust-portal-collector-policy.json` maps to one AWS service:

- `TrustPortalCollectorSTS` — identity detection (`sts:GetCallerIdentity`)
- `TrustPortalCollectorIAMReadOnly` — users, MFA, password policy, access keys, credential reports
- `TrustPortalCollectorRDSReadOnly` — instances, clusters, snapshots, subnet groups
- `TrustPortalCollectorS3ReadOnly` — bucket list, encryption, versioning, policy, ACL, replication, logging, public access block
- `TrustPortalCollectorEC2ReadOnly` — security groups, VPCs, subnets, instances, snapshots, volumes, network ACLs, flow logs
- `TrustPortalCollectorELBReadOnly` — load balancers, listeners, target groups, SSL policies
- `TrustPortalCollectorACMReadOnly` — certificates
- `TrustPortalCollectorElastiCacheReadOnly` — cache clusters, snapshots, replication groups
- `TrustPortalCollectorECSReadOnly` — clusters, services, task definitions
- `TrustPortalCollectorKMSReadOnly` — keys, rotation status, aliases
- `TrustPortalCollectorCloudTrailReadOnly` — trails, trail status, event selectors
- `TrustPortalCollectorCloudWatchLogsReadOnly` — log groups, log streams (metadata only)

To remove a service from coverage, delete its SID block and re-apply. The
portal will continue to operate; the relevant per-service checks will
simply report `skipped` or `error` results.

## Non-AWS deployments

If you're running the portal outside AWS, none of these files are
required. Configure the AWS collector in `access-keys` credential mode
with an IAM user's long-lived credentials, or disable the AWS collector
entirely. See the main repo README for alternatives.
