# Shared REST API plumbing used by all four stages below.
resource "aws_api_gateway_rest_api" "api" {
  name = "apigw-006-fixture-api"
}

resource "aws_api_gateway_resource" "resource" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "example"
}

resource "aws_api_gateway_method" "method" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.resource.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "integration" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = aws_api_gateway_resource.resource.id
  http_method = aws_api_gateway_method.method.http_method
  type        = "MOCK"
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.api.id

  depends_on = [aws_api_gateway_integration.integration]
}

# ---------------------------------------------------------------------------
# Scenario: no-method-logging-configuration
# Stage has no aws_api_gateway_method_settings covering it at all, so
# CloudWatch execution logging is effectively off.
# ---------------------------------------------------------------------------
resource "aws_api_gateway_stage" "no_method_logging" {
  stage_name    = "no-log"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.deployment.id
}

# ---------------------------------------------------------------------------
# Scenario: partial-method-logging-coverage
# Stage has a method-level logging configuration, but it only covers a
# specific method/path rather than every method and path (no catch-all).
# ---------------------------------------------------------------------------
resource "aws_api_gateway_stage" "partial_coverage" {
  stage_name    = "partial"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.deployment.id
}

resource "aws_api_gateway_method_settings" "partial_coverage_settings" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  stage_name  = "partial"
  method_path = "example/GET"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
  }
}

# ---------------------------------------------------------------------------
# Scenario: logging-level-not-accepted
# Stage has a catch-all method-level logging configuration, but the
# logging level is not INFO or ERROR.
# ---------------------------------------------------------------------------
resource "aws_api_gateway_stage" "bad_level" {
  stage_name    = "badlevel"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.deployment.id
}

resource "aws_api_gateway_method_settings" "bad_level_settings" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  stage_name  = "badlevel"
  method_path = "*/*"

  settings {
    metrics_enabled = true
    logging_level   = "OFF"
  }
}

# ---------------------------------------------------------------------------
# Scenario: logging-disabled-for-some-method
# Stage has an accepted catch-all logging configuration, but a narrower
# method-level setting turns execution logging off for a specific method.
# ---------------------------------------------------------------------------
resource "aws_api_gateway_stage" "disabled_for_some_method" {
  stage_name    = "disabled-method"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.deployment.id
}

resource "aws_api_gateway_method_settings" "disabled_for_some_method_catch_all" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  stage_name  = "disabled-method"
  method_path = "*/*"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
  }
}

resource "aws_api_gateway_method_settings" "disabled_for_some_method_specific" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  stage_name  = "disabled-method"
  method_path = "example/GET"

  settings {
    metrics_enabled = true
    logging_level   = "OFF"
  }
}
