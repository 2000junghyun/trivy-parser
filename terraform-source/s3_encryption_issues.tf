# S3 buckets with encryption misconfigurations
# This should trigger USER-003 custom policy (KMS encryption requirement)
# and potentially Trivy's built-in encryption checks

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-2"
}

# BAD: Using AES256 instead of KMS
resource "aws_s3_bucket" "aes_encryption" {
  bucket = "company-aes-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "aes_encryption" {
  bucket = aws_s3_bucket.aes_encryption.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# BAD: No encryption at all
resource "aws_s3_bucket" "no_encryption" {
  bucket = "company-unencrypted-bucket"
}

# BAD: Bucket without proper versioning and public access not blocked
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "company-insecure-public-bucket"
}

resource "aws_s3_bucket_public_access_block" "insecure_bucket" {
  bucket = aws_s3_bucket.insecure_bucket.id

  # BAD: Public access is allowed
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# GOOD: KMS encryption properly configured
resource "aws_s3_bucket" "kms_encrypted" {
  bucket = "company-secure-kms-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kms_encrypted" {
  bucket = aws_s3_bucket.kms_encrypted.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:ap-northeast-2:123456789012:key/12345678-1234-1234-1234-123456789012"
    }
  }
}

# GOOD: Public access properly blocked
resource "aws_s3_bucket_public_access_block" "kms_encrypted" {
  bucket = aws_s3_bucket.kms_encrypted.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
