output "task_role_arn" {
  description = "ARN of the trust-portal ECS task role. Reference this in your ECS task definition."
  value       = aws_iam_role.task_role.arn
}

output "task_role_name" {
  description = "Name of the trust-portal ECS task role."
  value       = aws_iam_role.task_role.name
}

output "collector_role_arn" {
  description = "ARN of the read-only collector role. Pre-fill this in the portal's collector setup wizard."
  value       = aws_iam_role.collector_role.arn
}

output "collector_role_name" {
  description = "Name of the read-only collector role."
  value       = aws_iam_role.collector_role.name
}
