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
  description = "Explicit opt-in. Keep false for validation and local-only use."
}
variable "aws_region" {
  type    = string
  default = "us-east-1"
}
variable "project_name" {
  type    = string
  default = "cloudshield-lab"
}
provider "aws" {
  region                      = var.aws_region
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}
data "aws_caller_identity" "current" {
  count = var.enable_lab_resources ? 1 : 0
}
resource "aws_s3_bucket" "evidence" {
  count  = var.enable_lab_resources ? 1 : 0
  bucket = "${var.project_name}-evidence-${data.aws_caller_identity.current[0].account_id}"
}
resource "aws_s3_bucket_public_access_block" "evidence" {
  count                   = var.enable_lab_resources ? 1 : 0
  bucket                  = aws_s3_bucket.evidence[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  count  = var.enable_lab_resources ? 1 : 0
  bucket = aws_s3_bucket.evidence[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_versioning" "evidence" {
  count  = var.enable_lab_resources ? 1 : 0
  bucket = aws_s3_bucket.evidence[0].id
  versioning_configuration {
    status = "Enabled"
  }
}
data "aws_iam_policy_document" "trail" {
  count = var.enable_lab_resources ? 1 : 0
  statement {
    sid       = "CloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.evidence[0].arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "CloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence[0].arn}/AWSLogs/${data.aws_caller_identity.current[0].account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}
resource "aws_s3_bucket_policy" "trail" {
  count  = var.enable_lab_resources ? 1 : 0
  bucket = aws_s3_bucket.evidence[0].id
  policy = data.aws_iam_policy_document.trail[0].json
}
resource "aws_cloudtrail" "audit" {
  count                         = var.enable_lab_resources ? 1 : 0
  name                          = "${var.project_name}-audit"
  s3_bucket_name                = aws_s3_bucket.evidence[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  depends_on                    = [aws_s3_bucket_policy.trail]
}
resource "aws_securityhub_account" "enabled" {
  count = var.enable_lab_resources ? 1 : 0
}
