resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_launch_template" "lt" {
  name          = "as006-lt"
  image_id      = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
}

# Subnet used by the single-subnet scenario (its own AZ, referenced only once).
resource "aws_subnet" "single" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}

# Two subnets sharing the same AZ, used by the subnets-in-single-availability-zone scenario.
resource "aws_subnet" "shared_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}

resource "aws_subnet" "shared_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-east-1b"
}

# Scenario: no-placement-specified
# No availability_zones and no vpc_zone_identifier declared at all.
resource "aws_autoscaling_group" "no_placement" {
  name             = "as006-no-placement"
  min_size         = 1
  max_size         = 1
  desired_capacity = 1

  launch_template {
    id = aws_launch_template.lt.id
  }
}

# Scenario: single-availability-zone
# A single declared Availability Zone and no subnets.
resource "aws_autoscaling_group" "single_zone" {
  name               = "as006-single-zone"
  min_size           = 1
  max_size           = 1
  desired_capacity   = 1
  availability_zones = ["us-east-1a"]

  launch_template {
    id = aws_launch_template.lt.id
  }
}

# Scenario: single-subnet
# No availability_zones, exactly one subnet reference.
resource "aws_autoscaling_group" "single_subnet" {
  name                = "as006-single-subnet"
  min_size            = 1
  max_size            = 1
  desired_capacity    = 1
  vpc_zone_identifier = [aws_subnet.single.id]

  launch_template {
    id = aws_launch_template.lt.id
  }
}

# Scenario: subnets-in-single-availability-zone
# No availability_zones, two subnets that both reside in the same Availability Zone.
resource "aws_autoscaling_group" "shared_subnet_zone" {
  name                = "as006-shared-subnet-zone"
  min_size            = 1
  max_size            = 1
  desired_capacity    = 1
  vpc_zone_identifier = [aws_subnet.shared_a.id, aws_subnet.shared_b.id]

  launch_template {
    id = aws_launch_template.lt.id
  }
}

# Scenarios "placement-in-single-availability-zone" and
# "subnet-outside-declared-availability-zones" are both only reached by evaluateCombinedZones(),
# which requires an aws_autoscaling_group with BOTH availability_zones and vpc_zone_identifier
# set (each fewer than 2 zones). The AWS Terraform provider's aws_autoscaling_group schema
# declares availability_zones and vpc_zone_identifier as mutually exclusive
# (ConflictsWith), so `terraform validate` rejects any configuration that sets both
# arguments, regardless of their values or whether they resolve at plan time. There is no
# valid HCL construct that can set both attributes on a single aws_autoscaling_group resource
# without failing validation, so these two scenarios cannot be triggered in this fixture.
