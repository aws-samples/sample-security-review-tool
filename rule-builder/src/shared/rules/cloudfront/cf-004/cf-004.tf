# CF-004: CloudFront distributions must only accept traffic over HTTPS.
#
# This fixture intentionally creates non-compliant aws_cloudfront_distribution
# resources to trigger each remediation scenario. The control's evaluate()
# checks scenarios in order and returns on the first match, so each scenario
# is exercised on a separate distribution.
#
# NOTE on `missing-default-viewer-protocol-policy`:
# The AWS Terraform provider marks `viewer_protocol_policy` as a Required
# attribute on `default_cache_behavior`. Omitting it causes terraform validate
# to fail before any plan is produced, so the scenario cannot be expressed
# directly in valid HCL. The closest faithful fixture is the
# `default-viewer-protocol-policy-allows-http` distribution below, which
# exercises a default cache behavior that does not enforce HTTPS. The
# "missing" scenario is therefore documented but not separately exercised
# in this Terraform fixture.

# Scenario: default-viewer-protocol-policy-allows-http
# Default cache behavior explicitly permits plaintext HTTP via "allow-all".
resource "aws_cloudfront_distribution" "default_allows_http" {
  enabled = true

  origin {
    domain_name = "example-default-allows-http.example.com"
    origin_id   = "primary-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "primary-origin"
    viewer_protocol_policy = "allow-all"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

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
    cloudfront_default_certificate = true
  }
}

# Scenario: additional-cache-behavior-allows-http
# Default cache behavior is compliant (redirects HTTP to HTTPS) but an
# ordered_cache_behavior permits plaintext HTTP via "allow-all".
resource "aws_cloudfront_distribution" "additional_allows_http" {
  enabled = true

  origin {
    domain_name = "example-additional-allows-http.example.com"
    origin_id   = "primary-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "primary-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  ordered_cache_behavior {
    path_pattern           = "/legacy/*"
    target_origin_id       = "primary-origin"
    viewer_protocol_policy = "allow-all"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

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
    cloudfront_default_certificate = true
  }
}
