import { describe, it } from 'vitest';

describe('AS-005 Terraform: Auto Scaling group built from an existing EC2 instance id', () => {
  // The Terraform provider's aws_autoscaling_group resource has no argument that
  // bases the group on an existing EC2 instance id (the CloudFormation
  // AWS::AutoScaling::AutoScalingGroup InstanceId property has no counterpart).
  // A group is wired up only through launch_configuration, launch_template or
  // mixed_instances_policy, so this scenario cannot be expressed in Terraform
  // source without inventing an argument the reader would never see. Covered by
  // the CloudFormation test for this requirement instead.
  it.skip('has no Terraform representation: aws_autoscaling_group cannot be based on an instance id', () => {});
});
