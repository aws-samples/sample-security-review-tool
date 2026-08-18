# AS-005 fixture: Auto Scaling groups not using a launch template

# Supporting launch configuration for the LAUNCH_CONFIGURATION_ONLY finding
resource "aws_launch_configuration" "lc" {
  name          = "as-005-lc"
  image_id      = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
}

# Finding: LAUNCH_CONFIGURATION_ONLY
# Group uses a launch configuration only, with no launch template or mixed instances policy.
resource "aws_autoscaling_group" "launch_configuration_only" {
  name                 = "as-005-launch-configuration-only"
  launch_configuration = aws_launch_configuration.lc.name
  min_size             = 1
  max_size             = 2
  availability_zones   = ["us-east-1a"]
}

# Finding: MIXED_INSTANCES_POLICY_WITHOUT_LAUNCH_TEMPLATE
# Group defines a mixed instances policy whose launch_template_specification supplies
# neither a launch template id nor a launch template name, so no launch template is in effect.
resource "aws_autoscaling_group" "mixed_instances_no_template" {
  name                = "as-005-mixed-instances-no-template"
  min_size            = 1
  max_size            = 2
  availability_zones  = ["us-east-1a"]

  mixed_instances_policy {
    launch_template {
      launch_template_specification {
        version = "$Latest"
      }
    }

    instances_distribution {
      on_demand_base_capacity = 1
    }
  }
}

# Finding: UNUSABLE_LAUNCH_TEMPLATE_REFERENCE
# Group declares a launch_template block that supplies neither an id nor a name.
resource "aws_autoscaling_group" "unusable_launch_template_reference" {
  name               = "as-005-unusable-launch-template-reference"
  min_size           = 1
  max_size           = 2
  availability_zones = ["us-east-1a"]

  launch_template {
    version = "$Latest"
  }
}

# Findings NO_LAUNCH_SOURCE and EXISTING_INSTANCE_SOURCE are intentionally not represented
# here:
#  - NO_LAUNCH_SOURCE would require an aws_autoscaling_group with none of
#    launch_configuration, launch_template, or mixed_instances_policy set, but the AWS
#    provider schema enforces that exactly one of those three arguments must be present,
#    so such a resource cannot pass `terraform validate`.
#  - EXISTING_INSTANCE_SOURCE can never be produced by the Terraform adapter, since
#    usesExistingInstance() always returns false: an Auto Scaling group generated from an
#    existing EC2 instance has no Terraform equivalent (it is only reachable through the
#    "create from instance" workflow in the AWS console/CLI, not via the
#    aws_autoscaling_group resource).
