resource "aws_api_gateway_rest_api" "this" {
  name = "apigw-002-fixture"
}

resource "aws_api_gateway_resource" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_rest_api.this.root_resource_id
  path_part   = "items"
}

# Validator that enforces nothing (both body and parameter validation disabled)
resource "aws_api_gateway_request_validator" "no_enforcement" {
  name                        = "no-enforcement-validator"
  rest_api_id                 = aws_api_gateway_rest_api.this.id
  validate_request_body       = false
  validate_request_parameters = false
}

# Validator that only validates parameters (no body validation)
resource "aws_api_gateway_request_validator" "params_only" {
  name                        = "params-only-validator"
  rest_api_id                 = aws_api_gateway_rest_api.this.id
  validate_request_body       = false
  validate_request_parameters = true
}

# Scenario 1: no-request-validator
# Method has no request_validator_id set, so requests reach the backend unvalidated.
resource "aws_api_gateway_method" "no_validator" {
  rest_api_id   = aws_api_gateway_rest_api.this.id
  resource_id   = aws_api_gateway_resource.this.id
  http_method   = "GET"
  authorization = "NONE"
}

# Scenario 2: request-validator-enforces-nothing
# Method references a validator that has both body and parameter validation disabled.
resource "aws_api_gateway_method" "validator_enforces_nothing" {
  rest_api_id          = aws_api_gateway_rest_api.this.id
  resource_id          = aws_api_gateway_resource.this.id
  http_method          = "POST"
  authorization        = "NONE"
  request_validator_id = aws_api_gateway_request_validator.no_enforcement.id
}

# Scenario 3: parameter-validation-without-required-parameters
# Method references a validator that validates parameters only, but declares no
# query string or header parameters as required.
resource "aws_api_gateway_method" "no_required_parameters" {
  rest_api_id          = aws_api_gateway_rest_api.this.id
  resource_id          = aws_api_gateway_resource.this.id
  http_method          = "PUT"
  authorization        = "NONE"
  request_validator_id = aws_api_gateway_request_validator.params_only.id

  request_parameters = {
    "method.request.querystring.filter" = false
    "method.request.header.X-Trace-Id"  = false
  }
}
