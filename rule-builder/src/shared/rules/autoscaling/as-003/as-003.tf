resource "aws_launch_template" "lt" {
  name          = "as-003-lt"
  image_id      = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
}

# Scenario: missing-notification-configuration
# No aws_autoscaling_notification resource covers this group at all.
resource "aws_autoscaling_group" "asg_missing" {
  name                = "as-003-missing"
  desired_capacity    = 1
  min_size            = 1
  max_size            = 2
  availability_zones  = ["us-east-1a"]

  launch_template {
    id      = aws_launch_template.lt.id
    version = "$Latest"
  }
}

# Scenario: test-notification-only
resource "aws_autoscaling_group" "asg_test_only" {
  name                = "as-003-test-only"
  desired_capacity    = 1
  min_size            = 1
  max_size            = 2
  availability_zones  = ["us-east-1a"]

  launch_template {
    id      = aws_launch_template.lt.id
    version = "$Latest"
  }
}

resource "aws_autoscaling_notification" "test_only" {
  group_names   = [aws_autoscaling_group.asg_test_only.name]
  notifications = ["autoscaling:TEST_NOTIFICATION"]
  topic_arn     = "arn:aws:sns:us-east-1:123456789012:as-003-topic"
}

# Scenario: empty-event-type-list
resource "aws_autoscaling_group" "asg_empty_events" {
  name                = "as-003-empty-events"
  desired_capacity    = 1
  min_size            = 1
  max_size            = 2
  availability_zones  = ["us-east-1a"]

  launch_template {
    id      = aws_launch_template.lt.id
    version = "$Latest"
  }
}

resource "aws_autoscaling_notification" "empty_events" {
  group_names   = [aws_autoscaling_group.asg_empty_events.name]
  notifications = []
  topic_arn     = "arn:aws:sns:us-east-1:123456789012:as-003-topic"
}

# Scenario: unrecognized-event-type
resource "aws_autoscaling_group" "asg_unrecognized" {
  name                = "as-003-unrecognized"
  desired_capacity    = 1
  min_size            = 1
  max_size            = 2
  availability_zones  = ["us-east-1a"]

  launch_template {
    id      = aws_launch_template.lt.id
    version = "$Latest"
  }
}

resource "aws_autoscaling_notification" "unrecognized" {
  group_names   = [aws_autoscaling_group.asg_unrecognized.name]
  notifications = ["autoscaling:NOT_A_REAL_EVENT"]
  topic_arn     = "arn:aws:sns:us-east-1:123456789012:as-003-topic"
}

# Scenario: empty-destination-topic
resource "aws_autoscaling_group" "asg_empty_topic" {
  name                = "as-003-empty-topic"
  desired_capacity    = 1
  min_size            = 1
  max_size            = 2
  availability_zones  = ["us-east-1a"]

  launch_template {
    id      = aws_launch_template.lt.id
    version = "$Latest"
  }
}

resource "aws_autoscaling_notification" "empty_topic" {
  group_names   = [aws_autoscaling_group.asg_empty_topic.name]
  notifications = ["autoscaling:EC2_INSTANCE_LAUNCH", "autoscaling:EC2_INSTANCE_TERMINATE"]
  topic_arn     = ""
}
