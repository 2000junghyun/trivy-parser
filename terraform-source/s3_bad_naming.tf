# S3 bucket with naming convention violation
# This should trigger USER-001 custom policy (naming convention)

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# BAD: Bucket name doesn't start with 'company-'
resource "aws_s3_bucket" "bad_naming" {
  bucket = "my-random-bucket-12345"
  
  tags = {
    Environment = "dev"
    Purpose     = "testing"
  }
}

# BAD: Another bucket with wrong naming
resource "aws_s3_bucket" "another_bad" {
  bucket = "test-bucket-67890"
  
  tags = {
    Environment = "staging"
  }
}

# GOOD: This one follows naming convention
resource "aws_s3_bucket" "good_naming" {
  bucket = "company-data-bucket"
  
  tags = {
    Environment = "production"
  }
}

# BAD: No encryption configured (should also trigger USER-003)
resource "aws_s3_bucket" "no_encryption" {
  bucket = "unsecured-bucket"
}
