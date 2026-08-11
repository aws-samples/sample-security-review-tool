# S3-002: S3 bucket policies must not grant access to untrusted principals
#
# Scenario 1 (wildcard-principal-without-condition):
#   aws_s3_bucket.wildcard_principal_bucket carries an inline "policy" argument
#   whose Allow statement grants access to Principal "*" with no Condition
#   constraining who may assume it.
#
# Scenario 2 (service-principal-without-source-scope):
#   aws_s3_bucket_policy.service_principal_policy grants an AWS service
#   principal access via an Allow statement with no Condition restricting the
#   source account / source ARN / source owner.

resource "aws_s3_bucket" "wildcard_principal_bucket" {
  bucket = "s3-002-wildcard-principal-bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "WildcardPrincipalAllow"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::s3-002-wildcard-principal-bucket/*"
      }
    ]
  })
}

resource "aws_s3_bucket" "service_principal_bucket" {
  bucket = "s3-002-service-principal-bucket"
}

resource "aws_s3_bucket_policy" "service_principal_policy" {
  bucket = aws_s3_bucket.service_principal_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ServicePrincipalWithoutSourceScope"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::s3-002-service-principal-bucket/*"
      }
    ]
  })
}
