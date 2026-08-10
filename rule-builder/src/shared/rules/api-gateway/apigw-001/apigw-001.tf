# Fixture for APIGW-001: API Gateway stages must enable access logging
# with a log destination that has an explicit retention policy.
#
# Two scannable resources, each triggering one scenario:
#   1. aws_api_gateway_stage.no_logging       -> missing-access-logging
#   2. aws_apigatewayv2_stage.no_retention    -> missing-log-retention

############################################
# Scenario 1: missing-access-logging
# REST API stage with NO access_log_settings block at all.
############################################

resource "aws_api_gateway_rest_api" "example" {
  name = "apigw-001-example"
}

resource "aws_api_gateway_resource" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  parent_id   = aws_api_gateway_rest_api.example.root_resource_id
  path_part   = "items"
}

resource "aws_api_gateway_method" "example" {
  rest_api_id   = aws_api_gateway_rest_api.example.id
  resource_id   = aws_api_gateway_resource.example.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "example" {
  rest_api_id             = aws_api_gateway_rest_api.example.id
  resource_id             = aws_api_gateway_resource.example.id
  http_method             = aws_api_gateway_method.example.http_method
  integration_http_method = "GET"
  type                    = "HTTP"
  uri                     = "https://example.com/"
}

resource "aws_api_gateway_deployment" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id

  depends_on = [
    aws_api_gateway_integration.example,
  ]
}

resource "aws_api_gateway_stage" "no_logging" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.example.id
  deployment_id = aws_api_gateway_deployment.example.id

  # No access_log_settings block -> hasAccessLogging() returns false.
}

############################################
# Scenario 2: missing-log-retention
# HTTP API (v2) stage with access_log_settings pointing to a log group
# that has NO retention_in_days configured.
#
# Use a literal destination_arn (so it's a known string at plan time) that
# embeds the log group's literal name. The adapter matches the log group via
# substring on the literal name, then checks retention_in_days. The provider
# default for retention_in_days is 0 ("never expire"), which the adapter
# rightly treats as no retention configured.
############################################

resource "aws_cloudwatch_log_group" "no_retention" {
  name = "/aws/apigateway/apigw-001-no-retention"
  # Intentionally omit retention_in_days -> defaults to 0 -> hasRetention() returns false.
}

resource "aws_apigatewayv2_api" "example" {
  name          = "apigw-001-http-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "no_retention" {
  api_id      = aws_apigatewayv2_api.example.id
  name        = "default"
  auto_deploy = true

  access_log_settings {
    # Hardcoded ARN containing the literal log group name so the adapter can
    # resolve it at plan time without depending on (known after apply) values.
    destination_arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/apigw-001-no-retention"
    format          = "$context.requestId"
  }
}
