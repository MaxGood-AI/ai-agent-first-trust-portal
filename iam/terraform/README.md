# Trust Portal IAM — Terraform module

Provisions the two IAM roles the `ai-agent-first-trust-portal` needs when
deployed on AWS ECS Fargate in the **same AWS account** as the resources
its evidence collectors will scan.

## What this creates

- **`trust-portal-task-role`** — the ECS task role that runs the portal
  container. Has only the permissions the portal itself needs: Secrets
  Manager read, CloudWatch Logs write, and `sts:AssumeRole` scoped to the
  collector role.
- **`trust-portal-collector-role`** — a read-only scanning identity that
  the task role assumes at collection time. The portal exercises scan
  permissions only during `AssumeRole` calls, so CloudTrail records a clean
  boundary between portal operation and evidence collection.

The IAM policy for the collector role is loaded from
[`../trust-portal-collector-policy.json`](../trust-portal-collector-policy.json),
which is the single source of truth and is also read by the portal's UI
when showing the admin which permissions the collector needs.

## Usage

```hcl
module "trust_portal_iam" {
  source = "github.com/<your-fork>/ai-agent-first-trust-portal//iam/terraform"

  # Optional overrides:
  task_role_name      = "trust-portal-task-role"
  collector_role_name = "trust-portal-collector-role"

  # ARNs of the Secrets Manager secrets the portal task reads.
  # Wildcards allowed if you name them with a common prefix.
  task_secret_arns = [
    "arn:aws:secretsmanager:ca-central-1:123456789012:secret:trust-portal/*"
  ]

  tags = {
    Project     = "trust-portal"
    Environment = "production"
  }
}
```

Reference the outputs in your ECS task definition:

```hcl
resource "aws_ecs_task_definition" "trust_portal" {
  # ...
  task_role_arn      = module.trust_portal_iam.task_role_arn
  execution_role_arn = aws_iam_role.ecs_execution_role.arn
  # ...
}
```

After `terraform apply`, the portal will detect both roles automatically
via its onboarding wizard (`/admin/setup/collectors`) using
`sts:GetCallerIdentity`. The wizard pre-fills the collector role ARN
based on the detected account ID.

## What this does NOT create

- The ECS task definition, service, cluster, ALB, RDS, or Route53 records.
  This module is scoped to IAM only so it can be consumed independently of
  your broader infrastructure layout.
- The `ecs-execution-role` that ECS needs to pull images from ECR and
  write initial task logs. That's part of your ECS infrastructure, not
  the portal.
- The Secrets Manager secrets themselves. Create those separately and pass
  their ARNs via `task_secret_arns`.

## Testing

Validate the module shape without applying:

```bash
cd iam/terraform
terraform init
terraform validate
```

## Security posture

- Collector role is **read-only** — no write, no delete, no IAM mutation.
- Task role has **no direct scan permissions** — all scanning happens
  through the explicit `AssumeRole` into the collector role.
- Both roles are **least-privilege**: the task role only touches Secrets
  Manager secrets you whitelist via `task_secret_arns`, and the collector
  role only reads the services listed in
  `trust-portal-collector-policy.json`.
- Rotation-friendly: the encryption key for stored collector credentials
  lives in Secrets Manager (not in this module) and can be rotated without
  changing IAM.

## Customization

To restrict the collector role's read scope (e.g., remove CloudTrail from
coverage), edit the canonical policy file
[`../trust-portal-collector-policy.json`](../trust-portal-collector-policy.json)
and re-apply. Terraform will detect the file change and update the inline
role policy.
