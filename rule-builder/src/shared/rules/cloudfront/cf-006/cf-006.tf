# CF-006 fixture: CloudFront distributions must enable origin access control.
#
# The control's evaluate() returns on the first matching scenario per resource,
# so we use two separate aws_cloudfront_distribution resources — one per
# remediation scenario.
#
# Scenario 1 (s3-origin-without-access-control):
#   A distribution with an S3 origin (s3_origin_config block present) that has
#   neither a legacy origin_access_identity nor an origin_access_control_id
#   resolving to an aws_cloudfront_origin_access_control resource.
#
# Scenario 2 (non-s3-oac-eligible-origin-without-access-control):
#   A distribution with a non-S3 OAC-eligible origin (Lambda Function URL
#   domain) that does not have an origin_access_control_id resolving to an
#   existing OAC.

############################################
# Scenario 1: Unprotected S3 origin
############################################
resource "aws_cloudfront_distribution" "s3_origin_unprotected" {
  enabled             = true
  default_root_object = "index.html"
  comment             = "CF-006 scenario: unprotected S3 origin"

  origin {
    origin_id   = "s3-unprotected-origin"
    domain_name = "cf-006-fixture-bucket.s3.us-east-1.amazonaws.com"

    # Legacy OAI is empty, and no origin_access_control_id is set,
    # so this S3 origin is unprotected.
    s3_origin_config {
      origin_access_identity = ""
    }
  }

  default_cache_behavior {
    target_origin_id       = "s3-unprotected-origin"
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
}

############################################
# Scenario 2: Unprotected non-S3 OAC-eligible origin (Lambda Function URL)
############################################
resource "aws_cloudfront_distribution" "lambda_url_origin_unprotected" {
  enabled = true
  comment = "CF-006 scenario: unprotected Lambda URL origin"

  origin {
    origin_id   = "lambda-url-unprotected-origin"
    # Matches LAMBDA_URL_DOMAIN_PATTERN: *.lambda-url.<region>.on.aws
    domain_name = "abcdefghijklmnopqrstuvwxyz123456.lambda-url.us-east-1.on.aws"

    # No origin_access_control_id set -> unprotected OAC-eligible origin.
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "lambda-url-unprotected-origin"
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
}
