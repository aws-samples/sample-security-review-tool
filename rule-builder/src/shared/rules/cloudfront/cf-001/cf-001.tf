# CF-001 fixture: trigger remediation scenarios for the rule
# enforcing a minimum viewer TLS version of 1.2 on CloudFront distributions.
#
# Cf001Control.evaluate() checks, in order:
#   1. missing-viewer-certificate         -> no viewer_certificate block
#   2. missing-minimum-protocol-version   -> block present, no minimum_protocol_version
#   3. insecure-minimum-protocol-version  -> block present, minimum_protocol_version is < TLSv1.2
#
# ----------------------------------------------------------------------------
# SCENARIOS NOT TRIGGERABLE VIA TERRAFORM
# ----------------------------------------------------------------------------
# Scenario "missing-viewer-certificate":
#   The aws_cloudfront_distribution resource schema (hashicorp/aws provider)
#   requires at least one `viewer_certificate` block. `terraform validate`
#   rejects configurations without it:
#     "Insufficient viewer_certificate blocks: At least 1 viewer_certificate
#      blocks are required."
#   Because the block is structurally mandatory in HCL, no Terraform plan
#   can have `values.viewer_certificate` absent/null, which is what
#   Cf001TfAdapter.hasViewerCertificate() detects.
#
# Scenario "missing-minimum-protocol-version":
#   When `minimum_protocol_version` is omitted from the viewer_certificate
#   block, the AWS provider populates it with the default value "TLSv1"
#   in the planned state. Cf001TfAdapter.hasMinimumProtocolVersion()
#   therefore always returns true for any Terraform plan that includes a
#   non-default-CloudFront-cert viewer_certificate, so this scenario is not
#   reachable via Terraform.
#
# Both scenarios remain reachable through other adapters (e.g. CloudFormation
# templates that omit ViewerCertificate or MinimumProtocolVersion), but not
# through the Terraform adapter, so they are intentionally not covered here.
# ----------------------------------------------------------------------------

############################################
# Scenario 3: insecure-minimum-protocol-version
# viewer_certificate set with a minimum_protocol_version that does not
# enforce TLS 1.2 or higher (TLSv1).
############################################
resource "aws_cloudfront_distribution" "insecure_minimum_protocol_version" {
  enabled         = true
  is_ipv6_enabled = false
  comment         = "cf-001 scenario: insecure-minimum-protocol-version"

  aliases = ["cdn-insecure-mpv.example.com"]

  origin {
    domain_name = "example-origin.example.com"
    origin_id   = "primary-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "primary-origin"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    # Custom ACM cert => cloudfront_default_certificate is false (so the
    # control does not short-circuit on usesDefaultCloudFrontCertificate()).
    # minimum_protocol_version is set to TLSv1, which is below TLS 1.2 and
    # therefore matches isInsecureMinimumProtocolVersion().
    acm_certificate_arn      = "arn:aws:acm:us-east-1:123456789012:certificate/22222222-2222-2222-2222-222222222222"
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1"
  }
}
