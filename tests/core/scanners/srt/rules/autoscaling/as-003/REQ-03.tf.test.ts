import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003TfAdapterFactory();

const assessedGroup: TerraformResource = {
  type: 'aws_autoscaling_group',
  name: 'assessed',
  address: 'aws_autoscaling_group.assessed',
  values: {
    name: 'assessed-asg',
    min_size: 1,
    max_size: 3,
  },
} as unknown as TerraformResource;

const otherGroup: TerraformResource = {
  type: 'aws_autoscaling_group',
  name: 'other',
  address: 'aws_autoscaling_group.other',
  values: {
    name: 'other-asg',
    min_size: 1,
    max_size: 3,
  },
} as unknown as TerraformResource;

function notificationFor(groupAddress: string): TerraformResource {
  return {
    type: 'aws_autoscaling_notification',
    name: 'scaling_events',
    address: 'aws_autoscaling_notification.scaling_events',
    values: {
      group_names: [groupAddress],
      notifications: [
        'autoscaling:EC2_INSTANCE_LAUNCH',
        'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
        'autoscaling:EC2_INSTANCE_TERMINATE',
        'autoscaling:EC2_INSTANCE_TERMINATE_ERROR',
      ],
      topic_arn: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
    },
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  return as003Control.run(factory.bind(context), context);
}

describe('AS-003 Terraform - notification configuration scoped to another Auto Scaling group', () => {
  // Primary behavior owned by this requirement: an aws_autoscaling_notification whose
  // group_names names a different group does not cover the assessed group.
  it('flags the assessed group when the only notification targets a different group', () => {
    const resources = [assessedGroup, otherGroup, notificationFor(otherGroup.address)];

    const result = run(assessedGroup, resources);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.assessed');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: identical project, except the notification's group_names points at
  // the assessed group - the verdict flips to no finding.
  it('does not flag the assessed group when the notification targets the assessed group', () => {
    const resources = [assessedGroup, otherGroup, notificationFor(assessedGroup.address)];

    const result = run(assessedGroup, resources);

    expect(result).toBeNull();
  });

  it('does not flag the other group that the notification targets', () => {
    const resources = [assessedGroup, otherGroup, notificationFor(otherGroup.address)];

    const result = run(otherGroup, resources);

    expect(result).toBeNull();
  });
});
