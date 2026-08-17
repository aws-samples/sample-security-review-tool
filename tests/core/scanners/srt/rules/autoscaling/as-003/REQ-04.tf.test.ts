import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003TfAdapterFactory();

const group: TerraformResource = {
  type: 'aws_autoscaling_group',
  name: 'app',
  address: 'aws_autoscaling_group.app',
  values: { name: 'app-asg', min_size: 1, max_size: 2 },
} as unknown as TerraformResource;

function notification(notifications: string[]): TerraformResource {
  return {
    type: 'aws_autoscaling_notification',
    name: 'app',
    address: 'aws_autoscaling_notification.app',
    values: {
      group_names: ['aws_autoscaling_group.app'],
      topic_arn: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
      notifications,
    },
  } as unknown as TerraformResource;
}

function scan(notifications: string[]) {
  const allResources = [group, notification(notifications)];
  const context: TfContext = { projectName: 'test-project', resource: group, allResources };
  return as003Control.run(factory.bind(context), context);
}

describe('AS-003 REQ-04 (Terraform): notification configuration listing only the test notification', () => {
  // Primary behavior owned by this requirement: a notification resource whose only
  // event is autoscaling:TEST_NOTIFICATION delivers no scaling event, so flag it.
  it('flags an Auto Scaling group whose only notification event is autoscaling:TEST_NOTIFICATION', () => {
    const result = scan(['autoscaling:TEST_NOTIFICATION']);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });

  // Opposite outcome: only the event type changes to a real scaling event.
  it('does not flag an Auto Scaling group whose notification event is a real scaling event', () => {
    const result = scan(['autoscaling:EC2_INSTANCE_LAUNCH']);

    expect(result).toBeNull();
  });

  it('does not flag when the test notification is listed alongside a real scaling event', () => {
    const result = scan(['autoscaling:TEST_NOTIFICATION', 'autoscaling:EC2_INSTANCE_LAUNCH_ERROR']);

    expect(result).toBeNull();
  });
});
