# APIGW-005 fixture
#
# Triggers all four remediation scenarios for APIGW-005:
#   1. missing-endpoint-configuration -> aws_api_gateway_rest_api.missing_endpoint_config
#   2. public-endpoint-type           -> aws_api_gateway_rest_api.public_endpoint
#   3. missing-vpc-endpoint           -> aws_api_gateway_rest_api.missing_vpc_endpoint
#   4. policy-excludes-private-path   -> aws_api_gateway_rest_api.policy_excludes_private_path
#
# A compliant-looking aws_vpc_endpoint (vpce_execute_api) is declared as a
# supporting resource for the execute-api service. Its mere presence in the
# plan also satisfies hasVpcCallers() for the "public-endpoint-type" scenario,
# and it is explicitly wired to the fourth API so the private access policy
# check can be exercised.

# Scenario 1: missing-endpoint-configuration
# No endpoint_configuration block at all -> defaults to a public endpoint.
resource "aws_api_gateway_rest_api" "missing_endpoint_config" {
  name = "apigw-005-missing-endpoint-config"
}

# Scenario 2: public-endpoint-type
# Endpoint type explicitly set to REGIONAL (not PRIVATE). hasVpcCallers() is
# satisfied by the presence of the aws_vpc_endpoint resource elsewhere in
# this plan.
resource "aws_api_gateway_rest_api" "public_endpoint" {
  name = "apigw-005-public-endpoint"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# Scenario 3: missing-vpc-endpoint
# Endpoint type is PRIVATE, but there is no associated VPC endpoint for
# execute-api at all.
resource "aws_api_gateway_rest_api" "missing_vpc_endpoint" {
  name = "apigw-005-missing-vpc-endpoint"

  endpoint_configuration {
    types = ["PRIVATE"]
  }
}

# Supporting resource: a compliant interface VPC endpoint for execute-api,
# used by the fourth scenario below.
resource "aws_vpc_endpoint" "vpce_execute_api" {
  vpc_id              = "vpc-12345678"
  service_name        = "com.amazonaws.us-east-1.execute-api"
  vpc_endpoint_type    = "Interface"
  subnet_ids           = ["subnet-12345678"]
  security_group_ids   = ["sg-12345678"]
  private_dns_enabled  = true
}

# Scenario 4: policy-excludes-private-path
# Endpoint type is PRIVATE and is associated with the compliant VPC endpoint
# above, but the access policy explicitly denies invocations arriving
# through that endpoint's VPC.
resource "aws_api_gateway_rest_api" "policy_excludes_private_path" {
  name = "apigw-005-policy-excludes-private-path"

  endpoint_configuration {
    types            = ["PRIVATE"]
    vpc_endpoint_ids = [aws_vpc_endpoint.vpce_execute_api.id]
  }

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Deny"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "*"
        Condition = {
          StringEquals = {
            "aws:sourceVpc" = "vpc-12345678"
          }
        }
      },
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "*"
      }
    ]
  })
}
