# S3-001: S3 buckets must enable server access logging unless serving as a log destination.
#
# Scenario: enable-server-access-logging
# A plain aws_s3_bucket with no inline logging block, no companion
# aws_s3_bucket_logging resource targeting it, and not used as a target_bucket
# by any aws_s3_bucket_logging resource. This triggers the finding.
resource "aws_s3_bucket" "noncompliant" {
  bucket = "s3-001-noncompliant-bucket"
}
