# LAMBDA-011: Lambda functions must have CloudWatch alarms for monitoring
#
# Scenario: missing-monitoring-alarm
# This Lambda function has no associated aws_cloudwatch_metric_alarm resource
# in the AWS/Lambda namespace covering it, which triggers the rule's only finding.

resource "aws_lambda_function" "unmonitored" {
  function_name = "lambda-011-unmonitored"
  role          = "arn:aws:iam::123456789012:role/lambda-011-role"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "function.zip"
}
