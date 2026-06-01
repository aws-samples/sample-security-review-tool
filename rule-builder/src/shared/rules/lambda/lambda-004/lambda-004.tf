# LAMBDA-004: Lambda functions must have X-Ray tracing enabled
# Scenario: missing-tracing-configuration
# This Lambda function omits the tracing_config block entirely, so
# hasTracingConfigured() returns false and the control flags it.

resource "aws_lambda_function" "no_tracing" {
  function_name = "lambda-004-missing-tracing"
  role          = "arn:aws:iam::123456789012:role/lambda-exec-role"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "lambda.zip"
}
