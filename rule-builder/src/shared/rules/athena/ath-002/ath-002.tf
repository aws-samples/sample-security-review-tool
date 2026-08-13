# Scenario: missing-output-location
# Workgroup has no result_configuration / output_location and does not use
# Athena managed query results storage, so no output bucket can be identified.
resource "aws_athena_workgroup" "missing_output" {
  name = "ath-002-missing-output-wg"

  configuration {
    enforce_workgroup_configuration = true
  }
}

# Scenario: output-bucket-allows-insecure-transport
# Workgroup points at a real S3 bucket, but that bucket's policy does not
# contain a Deny statement enforcing aws:SecureTransport.
resource "aws_s3_bucket" "insecure_results" {
  bucket = "ath-002-insecure-results"
}

resource "aws_s3_bucket_policy" "insecure_results" {
  bucket = aws_s3_bucket.insecure_results.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::ath-002-insecure-results/*"
      }
    ]
  })
}

resource "aws_athena_workgroup" "insecure_output_bucket" {
  name = "ath-002-insecure-output-wg"

  configuration {
    result_configuration {
      output_location = "s3://${aws_s3_bucket.insecure_results.bucket}/results/"
    }
  }
}
