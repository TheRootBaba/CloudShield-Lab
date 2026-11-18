variable "aws_region" {
  description = "AWS region used for security telemetry."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix for CloudShield Lab resources."
  type        = string
  default     = "cloudshield-lab"

  validation {
    condition     = length(trimspace(var.project_name)) > 0
    error_message = "project_name must not be empty."
  }
}
