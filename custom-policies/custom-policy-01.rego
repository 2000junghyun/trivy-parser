# METADATA
# title: "S3 bucket must have a specific name pattern"
# description: |
#   Custom check to ensure S3 bucket names follow naming convention
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: USER-001
#   avd_id: USER-001
#   provider: aws
#   service: s3
#   severity: MEDIUM
#   short_code: s3-naming-convention
#   recommended_action: Use proper naming convention for S3 buckets (must start with 'company-')
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
package user.aws.s3.naming

import rego.v1

# Check if bucket name starts with company prefix
deny contains res if {
	some bucket in input.aws.s3.buckets
	not startswith(bucket.name.value, "company-")
	
	res := result.new(
		sprintf("S3 bucket '%s' does not follow naming convention (must start with 'company-')", [bucket.name.value]),
		bucket.name,
	)
}