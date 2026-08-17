import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003TfAdapterFactory();

const asg: TerraformResource = {
  type: 'aws_autoscaling_group',
  name: 'app',
  address: 'aws_autoscaling_group.app',
  values: {
    name: 'app-asg',
    min_size: 1,
    max_size: 3,
    launch_template: [{ id: 'aws_launch_template.app' }],
  },
} as unknown as TerraformResource;

function scan(allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: asg,
    allResources,
  };
  return as003Control.run(factory.bind(context), context);
}

describe('AS-003 Terraform - empty notification configuration collection', () => {
  // Primary behavior owned by this requirement: the notification resource is
  // declared, but its collection of covered groups has no entries, so the group
  // ends up with no notification target at all.
  it('flags an Auto Scaling group when the declared notification resource covers no groups', () => {
    const notification: TerraformResource = {
      type: 'aws_autoscaling_notification',
      name: 'scaling',
      address: 'aws_autoscaling_notification.scaling',
      values: {
        group_names: [],
        topic_arn: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
        notifications: [
          'autoscaling:EC2_INSTANCE_LAUNCH',
          'autoscaling:EC2_INSTANCE_TERMINATE',
        ],
      },
    } as unknown as TerraformResource;

    const result = scan([asg, notification]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });

  // Opposite outcome: identical notification resource, except its collection of
  // covered groups contains this group.
  it('does not flag an Auto Scaling group when the declared notification resource lists this group', () => {
    const notification: TerraformResource = {
      type: 'aws_autoscaling_notification',
      name: 'scaling',
      address: 'aws_autoscaling_notification.scaling',
      values: {
        group_names: ['aws_autoscaling_group.app'],
        topic_arn: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
        notifications: [
          'autoscaling:EC2_INSTANCE_LAUNCH',
          'autoscaling:EC2_INSTANCE_TERMINATE',
        ],
      },
    } as unknown as TerraformResource;

    const result = scan([asg, notification]);

    expect(result).toBeNull();
  });
});
