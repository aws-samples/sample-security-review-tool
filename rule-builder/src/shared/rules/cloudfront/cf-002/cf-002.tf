# CF-002: CloudFront distributions require WAF protection
# Scenario: missing-web-acl-association
# This distribution intentionally omits `web_acl_id`, triggering the finding.

resource "aws_cloudfront_distribution" "no_waf" {
  enabled             = true
  default_root_object = "index.html"
  comment             = "CF-002 fixture - no WAF web ACL associated"

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

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  # web_acl_id intentionally omitted to trigger CF-002.
}
