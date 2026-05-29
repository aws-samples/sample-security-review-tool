# CF-003: CloudFront distributions must enable access logging
#
# Scenario: no-access-logging
# A CloudFront distribution with neither an inline `logging_config` block nor a
# complete external log delivery pipeline (no aws_cloudwatch_log_delivery_source
# referencing this distribution and no aws_cloudwatch_log_delivery_destination)
# triggers the finding.

resource "aws_cloudfront_distribution" "no_logging" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "CF-003 fixture - missing access logging"
  default_root_object = "index.html"

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
    cloudfront_default_certificate = true
  }

  # NOTE: intentionally no `logging_config` block to trigger the finding.
}
