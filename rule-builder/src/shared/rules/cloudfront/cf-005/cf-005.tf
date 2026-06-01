# CF-005 fixture: trigger every remediation scenario.
#
# The control evaluates each CloudFront distribution and returns on the FIRST
# matching custom origin finding. We therefore use one distribution per
# scenario, each with a single custom origin configured to trip exactly one
# branch of the evaluate() chain.

# Scenario 1: custom-origin-http-only
# Custom origin uses origin_protocol_policy = "http-only".
resource "aws_cloudfront_distribution" "http_only" {
  enabled = true

  origin {
    domain_name = "origin-http-only.example.com"
    origin_id   = "origin-http-only"

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "http-only"
      origin_ssl_protocols     = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "origin-http-only"
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
}

# Scenario 2: custom-origin-match-viewer
# Custom origin uses origin_protocol_policy = "match-viewer".
resource "aws_cloudfront_distribution" "match_viewer" {
  enabled = true

  origin {
    domain_name = "origin-match-viewer.example.com"
    origin_id   = "origin-match-viewer"

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "match-viewer"
      origin_ssl_protocols     = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "origin-match-viewer"
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
}

# Scenario 3: custom-origin-legacy-ssl-protocol
# Custom origin uses https-only (good policy) but permits a legacy TLS version.
resource "aws_cloudfront_distribution" "legacy_ssl" {
  enabled = true

  origin {
    domain_name = "origin-legacy-ssl.example.com"
    origin_id   = "origin-legacy-ssl"

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = ["TLSv1", "TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "origin-legacy-ssl"
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
}

# Scenario 4: custom-origin-missing-ssl-protocols
# Custom origin uses https-only but the AWS provider requires
# origin_ssl_protocols to be set, so we cannot omit the key entirely. To still
# trigger the "missing" branch we declare an empty list, which the adapter
# treats as missing (length === 0) while the provider accepts it as a valid
# (resolvable) empty list of strings.
resource "aws_cloudfront_distribution" "missing_ssl" {
  enabled = true

  origin {
    domain_name = "origin-missing-ssl.example.com"
    origin_id   = "origin-missing-ssl"

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = []
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "origin-missing-ssl"
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
}
