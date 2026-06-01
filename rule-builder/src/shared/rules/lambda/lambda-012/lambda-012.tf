# LAMBDA-012: Lambda functions must have unique IAM execution roles.
# Scenario: shared-execution-role
# Two Lambda functions reference the same IAM role ARN, so each one will be
# flagged as sharing its execution role with another resource.

resource "aws_lambda_function" "first" {
  function_name = "lambda-012-first"
  role          = "arn:aws:iam::123456789012:role/shared-lambda-role"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "function.zip"
}

resource "aws_lambda_function" "second" {
  function_name = "lambda-012-second"
  role          = "arn:aws:iam::123456789012:role/shared-lambda-role"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "function.zip"
}
