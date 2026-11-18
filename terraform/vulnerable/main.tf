# INTENTIONALLY INSECURE TRAINING FIXTURES. Never use in a real/shared account.
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
variable "enable_lab_resources" {
  type        = bool
  default     = false
  description = "Explicit opt-in for an isolated disposable training account only."
}
variable "aws_region" {
  type    = string
  default = "us-east-1"
}
provider "aws" {
  region                      = var.aws_region
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}
resource "aws_s3_bucket" "intentionally_public" {
  count         = var.enable_lab_resources ? 1 : 0
  bucket_prefix = "cloudshield-insecure-lab-"
}
resource "aws_s3_bucket_public_access_block" "intentionally_disabled" {
  count                   = var.enable_lab_resources ? 1 : 0
  bucket                  = aws_s3_bucket.intentionally_public[0].id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
resource "aws_security_group" "intentionally_open" {
  count       = var.enable_lab_resources ? 1 : 0
  name_prefix = "cloudshield-insecure-lab-"
  description = "INTENTIONALLY INSECURE: public SSH ingress for detector validation"
  ingress {
    description = "INSECURE TEST ONLY"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

[executed on device: babam-desktop (5b84c11b-7f66-494f-9e6d-0dd5f16de169)]