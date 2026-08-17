import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const group: TerraformResource = {
  type: 'aws_autoscaling_group',
  name: 'app',
  address: 'aws_autoscaling_group.app',
  values: {
    name: 'app-asg',
    min_size: 1,
    max_size: 3,
  },
};

function notification(name: string, topic: string, notifications: string[]): TerraformResource {
  return {
    type: 'aws_autoscaling_notification',
    name,
    address: `aws_autoscaling_notification.${name}`,
    values: {
      group_names: ['aws_autoscaling_group.app'],
      topic_arn: topic,
      notifications,
    },
  };
}

function run(notifications: TerraformResource[]) {
  const allResources = [group, ...notifications];
  const context: TfContext = {
    projectName: 'as-003-project',
    resource: group,
    allResources,
  };
  const adapter = new As003TfAdapterFactory().bind(context);
  return as003Control.run(adapter, context);
}

describe('AS-003 Terraform - notification configurations limited to the test notification', () => {
  // Primary behavior owned by AS-003: only the four real scaling events count as coverage.
  it('flags an Auto Scaling group whose two notifications both cover only autoscaling:TEST_NOTIFICATION', () => {
    const result = run([
      notification('launch_alarm', 'aws_sns_topic.launch_alarm', ['autoscaling:TEST_NOTIFICATION']),
      notification('ops_alarm', 'aws_sns_topic.ops_alarm', ['autoscaling:TEST_NOTIFICATION']),
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
    expect(result?.issue).toMatch(/test notification/i);
  });

  // Opposite outcome: same two notifications, but one also covers a real terminate event.
  it('does not flag when one of the two notifications also covers a real terminate event', () => {
    const result = run([
      notification('launch_alarm', 'aws_sns_topic.launch_alarm', [
        'autoscaling:TEST_NOTIFICATION',
        'autoscaling:EC2_INSTANCE_TERMINATE',
      ]),
      notification('ops_alarm', 'aws_sns_topic.ops_alarm', ['autoscaling:TEST_NOTIFICATION']),
    ]);

    expect(result).toBeNull();
  });
});
