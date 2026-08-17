import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { As003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003TfAdapterFactory();

const group: TerraformResource = {
  type: 'aws_autoscaling_group',
  name: 'app',
  address: 'aws_autoscaling_group.app',
  values: { name: 'app-asg', min_size: 1, max_size: 3 },
};

function notification(name: string, notifications: string[], topic: string): TerraformResource {
  return {
    type: 'aws_autoscaling_notification',
    name,
    address: `aws_autoscaling_notification.${name}`,
    values: {
      group_names: ['aws_autoscaling_group.app'],
      notifications,
      topic_arn: topic,
    },
  };
}

function run(notifications: TerraformResource[]) {
  const allResources = [group, ...notifications];
  const context: TfContext = { projectName: 'test-project', resource: group, allResources };
  const adapter = factory.bind(context) as As003Adapter;
  return as003Control.run(adapter, context);
}

describe('AS-003 Terraform - two notification resources covering launch and terminate', () => {
  // Primary behavior owned by AS-003: launch/terminate/failure coverage via SNS satisfies the rule.
  it('passes when one notification covers instance launch and another covers instance terminate, each with its own topic', () => {
    const result = run([
      notification('launch', ['autoscaling:EC2_INSTANCE_LAUNCH'], 'arn:aws:sns:us-east-1:123456789012:asg-launch-events'),
      notification('terminate', ['autoscaling:EC2_INSTANCE_TERMINATE'], 'arn:aws:sns:us-east-1:123456789012:asg-terminate-events'),
    ]);

    expect(result).toBeNull();
  });

  // Opposite outcome: same two notifications and topics, but neither delivers a real scaling event.
  it('flags when both notifications cover only the test notification instead of launch or terminate events', () => {
    const result = run([
      notification('launch', ['autoscaling:TEST_NOTIFICATION'], 'arn:aws:sns:us-east-1:123456789012:asg-launch-events'),
      notification('terminate', ['autoscaling:TEST_NOTIFICATION'], 'arn:aws:sns:us-east-1:123456789012:asg-terminate-events'),
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });
});
