# S3 production buckets with versioning issues
# This should trigger USER-004 custom policy (production bucket versioning)

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# BAD: Production bucket without versioning
resource "aws_s3_bucket" "prod_no_versioning" {
  bucket = "company-prod-data-bucket"
  
  tags = {
    Environment = "production"
    Critical    = "true"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "prod_no_versioning" {
  bucket = aws_s3_bucket.prod_no_versioning.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-west-2:123456789012:key/prod-key-123"
    }
  }
}

# BAD: Another production bucket without versioning
resource "aws_s3_bucket" "production_logs" {
  bucket = "company-production-logs-bucket"
  
  tags = {
    Environment = "production"
    Type        = "logs"
  }
}

# BAD: Production bucket with versioning disabled explicitly
resource "aws_s3_bucket" "prod_versioning_disabled" {
  bucket = "company-prod-backup-bucket"
}

resource "aws_s3_bucket_versioning" "prod_versioning_disabled" {
  bucket = aws_s3_bucket.prod_versioning_disabled.id
  
  versioning_configuration {
    status = "Disabled"
  }
}

# GOOD: Production bucket with versioning enabled
resource "aws_s3_bucket" "prod_with_versioning" {
  bucket = "company-prod-secure-bucket"
  
  tags = {
    Environment = "production"
    Backup      = "enabled"
  }
}

resource "aws_s3_bucket_versioning" "prod_with_versioning" {
  bucket = aws_s3_bucket.prod_with_versioning.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "prod_with_versioning" {
  bucket = aws_s3_bucket.prod_with_versioning.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-west-2:123456789012:key/prod-key-456"
    }
  }
}

# GOOD: Non-production bucket (versioning not required by custom policy)
resource "aws_s3_bucket" "dev_bucket" {
  bucket = "company-dev-test-bucket"
  
  tags = {
    Environment = "development"
  }
}
