## AS-001: Auto Scaling Groups must have a default cooldown period configured (set to a nonzero value)
##
## The aws_autoscaling_group.default_cooldown attribute has a `number` type in the AWS
## provider schema. Terraform performs strict type checking against the provider schema
## during `validate`/`plan`, even for literal values and resolvable variables. A value such
## as an empty string ("") or a non-numeric string ("not-a-number") is rejected outright by
## the provider schema with "Inappropriate value for attribute \"default_cooldown\": a number
## is required" -- this happens before any AWS API call, so there is no way to express the
## "empty-cooldown" or "non-numeric-cooldown" remediation scenarios as valid Terraform HCL that
## still plans cleanly. Those two scenarios are therefore skipped here; they can only be
## exercised against non-Terraform sources (e.g. CloudFormation) where the attribute is a
## loosely-typed string.

resource "aws_autoscaling_group" "zero_cooldown" {
  name               = "asg-zero-cooldown"
  availability_zones = ["us-east-1a"]
  min_size           = 1
  max_size           = 2
  default_cooldown   = 0

  launch_template {
    id      = "lt-0123456789abcdef0"
    version = "$Latest"
  }
}

resource "aws_autoscaling_group" "negative_cooldown" {
  name               = "asg-negative-cooldown"
  availability_zones = ["us-east-1a"]
  min_size           = 1
  max_size           = 2
  default_cooldown   = -1

  launch_template {
    id      = "lt-0123456789abcdef0"
    version = "$Latest"
  }
}
