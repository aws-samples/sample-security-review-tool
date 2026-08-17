import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003TfAdapterFactory();

const asg: TerraformResource = {
  type: 'aws_autoscaling_group',
  name: 'app',
  address: 'aws_autoscaling_group.app',
  values: {
    name: 'app-asg',
    min_size: 1,
    max_size: 2,
  },
} as unknown as TerraformResource;

function notification(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_notification',
    name: 'app',
    address: 'aws_autoscaling_notification.app',
    values,
  } as unknown as TerraformResource;
}

function scan(notificationResource: TerraformResource) {
  const allResources = [asg, notificationResource];
  const context: TfContext = {
    projectName: 'test-project',
    resource: asg,
    allResources,
  };
  return as003Control.run(factory.bind(context), context);
}

describe('AS-003 Terraform - notification event list', () => {
  // Primary behavior for this requirement (REQ-07): the notification resource
  // targets the group and supplies a topic_arn but omits the notifications
  // argument entirely, so no scaling event is ever delivered - flag it.
  it('flags a group whose covering notification omits the notifications argument while giving a topic', () => {
    const result = scan(notification({
      group_names: ['aws_autoscaling_group.app'],
      topic_arn: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });

  // Opposite outcome: identical notification resource except the notifications
  // list is present and names real scaling events - nothing to flag.
  it('does not flag when the same notification lists real scaling events', () => {
    const result = scan(notification({
      group_names: ['aws_autoscaling_group.app'],
      topic_arn: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
      notifications: [
        'autoscaling:EC2_INSTANCE_LAUNCH',
        'autoscaling:EC2_INSTANCE_TERMINATE',
        'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
      ],
    }));

    expect(result).toBeNull();
  });
});
