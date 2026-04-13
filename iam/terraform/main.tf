############################################################
# ai-agent-first-trust-portal — IAM module
#
# Provisions the two IAM roles required for the trust portal's
# evidence collectors when deployed on AWS ECS Fargate in the
# same account as the resources being scanned:
#
#   - trust-portal-task-role:  runs the portal container
#   - trust-portal-collector-role: read-only scanning identity
#                                   assumed by the task role
#
# The portal never creates or modifies IAM resources at runtime;
# this module is applied once at deploy time and the portal
# detects the roles through its onboarding wizard.
############################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

############################################################
# Task role — runs the portal container
############################################################

resource "aws_iam_role" "task_role" {
  name = var.task_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowECSTaskAssume"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

# Minimum task-role permissions: Secrets Manager (for SECRET_KEY,
# COLLECTOR_ENCRYPTION_KEY, DATABASE_URL), CloudWatch Logs (self-logging),
# and sts:AssumeRole on the collector role only.
resource "aws_iam_role_policy" "task_role_base" {
  name = "${var.task_role_name}-base"
  role = aws_iam_role.task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecretsManagerRead"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = var.task_secret_arns
      },
      {
        Sid    = "CloudWatchLogsWrite"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      },
      {
        Sid      = "AssumeCollectorRole"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.collector_role.arn
      }
    ]
  })
}

############################################################
# Collector role — assumed by the task role at collection time
############################################################

resource "aws_iam_role" "collector_role" {
  name = var.collector_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowTaskRoleAssume"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:role/${var.task_role_name}"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

# Read-only scan permissions — loaded from the canonical policy JSON
# shipped with the trust portal repo so the file tree and Terraform
# share a single source of truth.
resource "aws_iam_role_policy" "collector_read_only" {
  name   = "${var.collector_role_name}-read-only"
  role   = aws_iam_role.collector_role.id
  policy = file("${path.module}/../trust-portal-collector-policy.json")
}
