terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
variable "enable_backup_resources" {
  type        = bool
  default     = false
  description = "Explicit opt-in. Validation creates no AWS resources."
}
variable "aws_region" {
  type    = string
  default = "us-east-1"
}
variable "project_name" {
  type    = string
  default = "cloudshield-lab"
  validation {
    condition     = can(regex("^[a-z0-9-]{3,24}$", var.project_name))
    error_message = "project_name must be 3-24 lowercase letters, digits or hyphens."
  }
}
variable "backup_uploader_principal_arn" {
  type        = string
  default     = ""
  description = "Deployment principal allowed to assume the dedicated backup upload role."
  validation {
    condition     = !var.enable_backup_resources || can(regex("^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:(role|user)/[A-Za-z0-9+=,.@_/-]+$", var.backup_uploader_principal_arn))
    error_message = "When enabled, provide a valid IAM role or user ARN as the backup uploader principal."
  }
}
variable "backup_external_id" {
  type        = string
  sensitive   = true
  default     = ""
  description = "Unique external ID required by the uploader role trust policy."
  validation {
    condition     = !var.enable_backup_resources || length(var.backup_external_id) >= 32
    error_message = "When enabled, backup_external_id must be at least 32 characters."
  }
}
variable "retention_days" {
  type        = number
  default     = 90
  description = "S3 Object Lock COMPLIANCE retention period."
  validation {
    condition     = var.retention_days >= 30 && var.retention_days <= 3650
    error_message = "retention_days must be between 30 and 3650."
  }
}
provider "aws" {
  region                      = var.aws_region
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}
data "aws_caller_identity" "current" {
  count = var.enable_backup_resources ? 1 : 0
}
locals {
  create = var.enable_backup_resources
  bucket = local.create ? "${var.project_name}-offsite-${data.aws_caller_identity.current[0].account_id}-${var.aws_region}" : ""
  prefix = "cloudshield/"
}
resource "aws_kms_key" "backup" {
  count                   = local.create ? 1 : 0
  description             = "CloudShield offsite backup encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}
resource "aws_kms_alias" "backup" {
  count         = local.create ? 1 : 0
  name          = "alias/${var.project_name}-offsite-backup"
  target_key_id = aws_kms_key.backup[0].key_id
}
resource "aws_s3_bucket" "backup" {
  count               = local.create ? 1 : 0
  bucket              = local.bucket
  object_lock_enabled = true
  force_destroy       = false
}
resource "aws_s3_bucket_public_access_block" "backup" {
  count                   = local.create ? 1 : 0
  bucket                  = aws_s3_bucket.backup[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_ownership_controls" "backup" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "backup" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_object_lock_configuration" "backup" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.backup]
}
resource "aws_s3_bucket_server_side_encryption_configuration" "backup" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.backup[0].arn
    }
    bucket_key_enabled = true
  }
}
data "aws_iam_policy_document" "bucket" {
  count = local.create ? 1 : 0
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.backup[0].arn, "${aws_s3_bucket.backup[0].arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}
resource "aws_s3_bucket_policy" "backup" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id
  policy = data.aws_iam_policy_document.bucket[0].json
}
data "aws_iam_policy_document" "assume" {
  count = local.create ? 1 : 0
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.backup_uploader_principal_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.backup_external_id]
    }
  }
}
resource "aws_iam_role" "uploader" {
  count                = local.create ? 1 : 0
  name                 = "${var.project_name}-offsite-backup-uploader"
  assume_role_policy   = data.aws_iam_policy_document.assume[0].json
  max_session_duration = 3600
}
data "aws_iam_policy_document" "uploader" {
  count = local.create ? 1 : 0
  statement {
    sid       = "ListBackupPrefix"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation", "s3:ListBucketMultipartUploads"]
    resources = [aws_s3_bucket.backup[0].arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${local.prefix}*"]
    }
  }
  statement {
    sid    = "WriteAndVerifyBackupObjects"
    effect = "Allow"
    actions = [
      "s3:PutObject", "s3:GetObject", "s3:GetObjectVersion",
      "s3:GetObjectRetention", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"
    ]
    resources = ["${aws_s3_bucket.backup[0].arn}/${local.prefix}*"]
  }
  statement {
    sid       = "UseBackupEncryptionKey"
    effect    = "Allow"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.backup[0].arn]
  }
}
resource "aws_iam_role_policy" "uploader" {
  count  = local.create ? 1 : 0
  name   = "cloudshield-offsite-backup"
  role   = aws_iam_role.uploader[0].id
  policy = data.aws_iam_policy_document.uploader[0].json
}
output "backup_bucket" {
  value       = local.bucket
  description = "S3 bucket for encrypted, compliance-retained workspace backups."
}
output "backup_prefix" {
  value = local.prefix
}
output "backup_kms_key_arn" {
  value = local.create ? aws_kms_key.backup[0].arn : null
}
output "backup_uploader_role_arn" {
  value = local.create ? aws_iam_role.uploader[0].arn : null
}
