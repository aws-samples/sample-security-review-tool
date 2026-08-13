# APIGW-008: API Gateway stages with caching enabled must have cache data
# encryption enabled for all cached methods.
#
# Scenario: unencrypted-cache
#   The stage has response caching enabled (via aws_api_gateway_stage
#   cache_cluster_enabled) and the associated aws_api_gateway_method_settings
#   resource enables caching for a method path but explicitly disables
#   cache_data_encrypted, so cached response data is not encrypted at rest.

resource "aws_api_gateway_rest_api" "api" {
  name = "apigw-008-example-api"
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

  triggers = {
    redeployment = "1"
  }

  depends_on = [aws_api_gateway_integration.integration]
}

resource "aws_api_gateway_stage" "stage" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.deployment.id

  cache_cluster_enabled = true
  cache_cluster_size    = "0.5"
}

# Catch-all method settings for the stage: caching is enabled for every
# method, but cache_data_encrypted is explicitly false, leaving cached
# response data unencrypted at rest.
resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  stage_name  = aws_api_gateway_stage.stage.stage_name
  method_path = "*/*"

  settings {
    caching_enabled      = true
    cache_data_encrypted = false
  }
}
