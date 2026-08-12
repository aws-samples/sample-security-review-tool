## APIGW-003 fixture
## Scenario 1 (missing-web-acl-association): a REST API stage with no web ACL
## association of any kind attached to it.
## Scenario 2 (legacy-web-acl-association): a REST API stage that is only
## protected by an end-of-life legacy (WAF Classic Regional) web ACL
## association, not a current-generation WAFv2 association.

resource "aws_api_gateway_rest_api" "api" {
  name = "apigw-003-fixture-api"
}

resource "aws_api_gateway_resource" "root" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "example"
}

resource "aws_api_gateway_method" "get" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.root.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "get" {
  rest_api_id             = aws_api_gateway_rest_api.api.id
  resource_id             = aws_api_gateway_resource.root.id
  http_method             = aws_api_gateway_method.get.http_method
  type                    = "MOCK"
  integration_http_method = "GET"
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.api.id

  depends_on = [aws_api_gateway_integration.get]
}

# --- Scenario: missing-web-acl-association -------------------------------
# No aws_wafv2_web_acl_association or aws_wafregional_web_acl_association
# resource covers this stage, so it is completely unprotected.
resource "aws_api_gateway_stage" "missing" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.deployment.id
  stage_name    = "missing"
}

# --- Scenario: legacy-web-acl-association ---------------------------------
# This stage is only covered by an end-of-life legacy (WAF Classic Regional)
# web ACL association, never by a current-generation aws_wafv2_web_acl_association.
resource "aws_api_gateway_stage" "legacy" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.deployment.id
  stage_name    = "legacy"
}

resource "aws_wafregional_web_acl" "legacy_acl" {
  name        = "apigw-003-legacy-acl"
  metric_name = "apigw003legacyacl"

  default_action {
    type = "ALLOW"
  }
}

resource "aws_wafregional_web_acl_association" "legacy" {
  resource_arn = "arn:aws:apigateway:us-east-1::/restapis/myapi123/stages/legacy"
  web_acl_id   = aws_wafregional_web_acl.legacy_acl.id
}
