resource "aws_launch_template" "lt" {
  name          = "as004-lt"
  image_id      = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
}

# Finding: INSTANCE_STATUS_HEALTH_CHECKS_ONLY
# ASG is attached to a target group directly (target_group_arns) and explicitly
# sets health_check_type = "EC2", so only instance status checks are used.
resource "aws_autoscaling_group" "direct_attachment" {
  name                = "as004-direct"
  min_size            = 1
  max_size            = 2
  desired_capacity    = 1
  availability_zones  = ["us-east-1a"]
  health_check_type   = "EC2"
  target_group_arns   = ["arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/as004-tg/abcdef1234567890"]

  launch_template {
    id      = aws_launch_template.lt.id
    version = "$Latest"
  }
}

# Finding: INSTANCE_STATUS_HEALTH_CHECKS_ONLY
# ASG has no health_check_type set at all (defaults to EC2 status checks only),
# and is attached to a load balancer externally via aws_autoscaling_attachment.
resource "aws_autoscaling_group" "external_lb_attachment" {
  name                = "as004-external-lb"
  min_size            = 1
  max_size            = 2
  desired_capacity    = 1
  availability_zones  = ["us-east-1a"]

  launch_template {
    id      = aws_launch_template.lt.id
    version = "$Latest"
  }
}

resource "aws_autoscaling_attachment" "external_lb" {
  autoscaling_group_name = aws_autoscaling_group.external_lb_attachment.id
  lb_target_group_arn    = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/as004-tg-2/abcdef1234567891"
}

# Finding: INSTANCE_STATUS_HEALTH_CHECKS_ONLY
# ASG has no health_check_type set (defaults to EC2 status checks only),
# and is attached to a traffic source externally via
# aws_autoscaling_traffic_source_attachment.
resource "aws_autoscaling_group" "external_traffic_source_attachment" {
  name                = "as004-external-ts"
  min_size            = 1
  max_size            = 2
  desired_capacity    = 1
  availability_zones  = ["us-east-1a"]

  launch_template {
    id      = aws_launch_template.lt.id
    version = "$Latest"
  }
}

resource "aws_autoscaling_traffic_source_attachment" "external_ts" {
  autoscaling_group_name = aws_autoscaling_group.external_traffic_source_attachment.id

  traffic_source {
    identifier = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/as004-tg-3/abcdef1234567892"
    type       = "elbv2"
  }
}
