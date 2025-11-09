# METADATA
# title: "Production S3 buckets must have versioning enabled"
# description: |
#   S3 buckets with 'prod' in their name must have versioning enabled for data protection
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: USER-004
#   avd_id: USER-004
#   provider: aws
#   service: s3
#   severity: HIGH
#   short_code: prod-s3-versioning
#   recommended_action: Enable versioning for production S3 buckets
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
package user.aws.s3.advanced

import rego.v1

# Helper function to check if bucket is production
is_production_bucket(bucket) if {
	contains(bucket.name.value, "prod")
}

is_production_bucket(bucket) if {
	contains(bucket.name.value, "production")
}

deny contains res if {
	some bucket in input.aws.s3.buckets
	is_production_bucket(bucket)
	not bucket.versioning
	
	res := result.new(
		sprintf("Production bucket '%s' must have versioning configured", [bucket.name.value]),
		bucket,
	)
}

deny contains res if {
	some bucket in input.aws.s3.buckets
	is_production_bucket(bucket)
	bucket.versioning
	not bucket.versioning.enabled.value
	
	res := result.new(
		sprintf("Production bucket '%s' must have versioning enabled", [bucket.name.value]),
		bucket.versioning.enabled,
	)
}

deny contains res if {
	some bucket in input.aws.s3.buckets
	is_production_bucket(bucket)
	bucket.versioning
	bucket.versioning.enabled.value
	bucket.versioning.mfadelete.value
	
	res := result.new(
		sprintf("Production bucket '%s' should not have MFA delete enabled in development environments", [bucket.name.value]),
		bucket.versioning.mfadelete,
	)
}