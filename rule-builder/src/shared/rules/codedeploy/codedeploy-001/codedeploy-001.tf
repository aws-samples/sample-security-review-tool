resource "aws_codedeploy_app" "app" {
  name             = "example-app"
  compute_platform = "Server"
}

resource "aws_iam_role" "codedeploy_role" {
  name = "example-codedeploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "codedeploy.amazonaws.com" }
      }
    ]
  })
}

# NO_ALARM_MONITORING: no alarm_configuration block at all, so no alarms are
# associated with the deployment group and deployments run unmonitored.
resource "aws_codedeploy_deployment_group" "no_alarm_config" {
  app_name              = aws_codedeploy_app.app.name
  deployment_group_name = "no-alarm-config"
  service_role_arn       = aws_iam_role.codedeploy_role.arn

  deployment_style {
    deployment_type   = "IN_PLACE"
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
  }
}
