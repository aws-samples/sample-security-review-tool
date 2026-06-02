# LAMBDA-015 fixture: Lambda container images must use a specific version tag
# instead of 'latest'. The single remediation scenario 'use-specific-version-tag'
# is triggered by the evaluate() method via two distinct code paths:
#   1. usesExplicitLatestTag() — image URI ends with ':latest'
#   2. hasNoTagOrDigest()      — image URI has neither ':<tag>' nor '@<digest>'
# Both functions report the same scenario, so we exercise both paths.

# Path 1: explicit ':latest' tag
resource "aws_lambda_function" "explicit_latest" {
  function_name = "lambda-015-explicit-latest"
  role          = "arn:aws:iam::123456789012:role/lambda-exec"
  package_type  = "Image"
  image_uri     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:latest"
}

# Path 2: no tag and no digest — resolves to 'latest' at pull time
resource "aws_lambda_function" "no_tag_or_digest" {
  function_name = "lambda-015-no-tag"
  role          = "arn:aws:iam::123456789012:role/lambda-exec"
  package_type  = "Image"
  image_uri     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app"
}
