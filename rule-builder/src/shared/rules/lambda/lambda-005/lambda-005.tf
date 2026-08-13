# Scenario 1: wildcard-action-and-resource
# Lambda execution role with an inline policy granting all actions on all resources.
resource "aws_iam_role" "wildcard_role" {
  name = "lambda-wildcard-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy" "wildcard_inline_policy" {
  name = "wildcard-inline-policy"
  role = aws_iam_role.wildcard_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "wildcard_fn" {
  function_name = "wildcard-fn"
  role          = aws_iam_role.wildcard_role.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  filename      = "lambda_function_payload.zip"
}

# Scenario 2: overly-broad-managed-policy
# Lambda execution role attached to the AWS-managed AdministratorAccess policy.
resource "aws_iam_role" "broad_policy_role" {
  name = "lambda-broad-policy-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "broad_policy_attachment" {
  role       = aws_iam_role.broad_policy_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_lambda_function" "broad_policy_fn" {
  function_name = "broad-policy-fn"
  role          = aws_iam_role.broad_policy_role.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  filename      = "lambda_function_payload.zip"
}
