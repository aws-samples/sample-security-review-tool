## APIGW-004: API Gateway methods/routes must require authorization
##
## Scenario: missing-authorization
## Triggered by an aws_api_gateway_method and an aws_apigatewayv2_route,
## each configured with no authorization (NONE / no authorizer_id), on a
## non-OPTIONS verb.

resource "aws_api_gateway_rest_api" "this" {
  name = "apigw-004-rest-api"
}

resource "aws_api_gateway_resource" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_rest_api.this.root_resource_id
  path_part   = "items"
}

# Non-compliant: authorization_type = NONE -> missing-authorization
resource "aws_api_gateway_method" "unauthorized" {
  rest_api_id   = aws_api_gateway_rest_api.this.id
  resource_id   = aws_api_gateway_resource.this.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_apigatewayv2_api" "this" {
  name          = "apigw-004-http-api"
  protocol_type = "HTTP"
}

# Non-compliant: authorization_type = NONE -> missing-authorization
resource "aws_apigatewayv2_route" "unauthorized" {
  api_id             = aws_apigatewayv2_api.this.id
  route_key          = "GET /items"
  authorization_type = "NONE"
}
