
# CODEBUILD-009: CodeBuild project service roles must include both
# s3:GetBucketAcl and s3:GetBucketLocation for any associated S3 bucket.
#
# Single finding type: MISSING_BUCKET_INSPECTION_PERMISSIONS
#
# The build project below sources from an S3 bucket, and its service role's
# attached inline policy grants only s3:GetBucketAcl (not s3:GetBucketLocation)
# on that bucket, so the bucket is missing required inspection permissions.

resource "aws_iam_role" "codebuild_role" {
  name = "codebuild-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "codebuild_role_policy" {
  name = "codebuild-role-policy"
  role = aws_iam_role.codebuild_role.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetBucketAcl"]
        Resource = "arn:aws:s3:::my-source-bucket"
      }
    ]
  })
}

resource "aws_codebuild_project" "example" {
  name         = "example-project"
  service_role = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:5.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type     = "S3"
    location = "my-source-bucket/source.zip"
  }
}
