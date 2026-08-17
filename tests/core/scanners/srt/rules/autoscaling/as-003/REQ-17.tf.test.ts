import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { As003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LAUNCH_AND_TERMINATE = [
  'autoscaling:EC2_INSTANCE_LAUNCH',
  'autoscaling:EC2_INSTANCE_TERMINATE',
];

const group: TerraformResource = {
  type: 'aws_autoscaling_group',
  name: 'app',
  address: 'aws_autoscaling_group.app',
  values: {
    name: 'app-asg',
    min_size: 1,
    max_size: 3,
    launch_template: [{ id: 'aws_launch_template.lt' }],
  },
};

function notification(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_notification',
    name: 'scaling',
    address: 'aws_autoscaling_notification.scaling',
    values,
  };
}

function run(notificationResource: TerraformResource): ScanResult | null {
  const allResources = [group, notificationResource];
  const context: TfContext = { projectName: 'test-project', resource: group, allResources };
  const adapter = new As003TfAdapterFactory().bind(context) as As003Adapter;
  return as003Control.run(adapter, context);
}

describe('AS-003 (Terraform) - notification configuration must name a destination topic', () => {
  // Primary behavior owned by this requirement: event types listed, but no topic_arn at all.
  it('flags an Auto Scaling group whose notification lists launch and terminate events with no topic_arn', () => {
    const result = run(notification({
      group_names: ['aws_autoscaling_group.app'],
      notifications: LAUNCH_AND_TERMINATE,
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
    expect(result?.issue).toMatch(/topic/i);
  });

  // Opposite outcome: same event types, but a destination topic is named.
  it('does not flag the same notification when a destination topic_arn is named', () => {
    const result = run(notification({
      group_names: ['aws_autoscaling_group.app'],
      notifications: LAUNCH_AND_TERMINATE,
      topic_arn: 'aws_sns_topic.scaling',
    }));

    expect(result).toBeNull();
  });
});
