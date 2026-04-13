variable "task_role_name" {
  description = "Name of the ECS task role that runs the portal container."
  type        = string
  default     = "trust-portal-task-role"
}

variable "collector_role_name" {
  description = "Name of the read-only role assumed by the task role at collection time."
  type        = string
  default     = "trust-portal-collector-role"
}

variable "task_secret_arns" {
  description = <<-EOT
    ARNs of the Secrets Manager secrets the portal task needs to read
    (e.g., SECRET_KEY, COLLECTOR_ENCRYPTION_KEY, DATABASE_URL). Use
    wildcards if you manage them with a common prefix.
  EOT
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to the IAM roles."
  type        = map(string)
  default     = {}
}
