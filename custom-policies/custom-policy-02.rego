# METADATA
# title: "S3 bucket must use KMS encryption"
# description: |
#   S3 buckets should use AWS KMS for encryption to have better control over encryption keys
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: USER-003
#   avd_id: USER-003
#   provider: aws
#   service: s3
#   severity: HIGH
#   short_code: s3-kms-encryption
#   recommended_action: Enable KMS encryption for S3 bucket
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
package user.aws.s3.encryption

import rego.v1

deny contains res if {
	some bucket in input.aws.s3.buckets
	bucket.encryption
	bucket.encryption.enabled.value
	bucket.encryption.algorithm.value != "aws:kms"
	
	res := result.new(
		sprintf("S3 bucket '%s' must use KMS encryption (currently using %s)", [bucket.name.value, bucket.encryption.algorithm.value]),
		bucket.encryption.algorithm,
	)
}

deny contains res if {
	some bucket in input.aws.s3.buckets
	not bucket.encryption
	
	res := result.new(
		sprintf("S3 bucket '%s' has no encryption configured", [bucket.name.value]),
		bucket,
	)
}

deny contains res if {
	some bucket in input.aws.s3.buckets
	bucket.encryption
	not bucket.encryption.enabled.value
	
	res := result.new(
		sprintf("S3 bucket '%s' has encryption disabled", [bucket.name.value]),
		bucket.encryption.enabled,
	)
}