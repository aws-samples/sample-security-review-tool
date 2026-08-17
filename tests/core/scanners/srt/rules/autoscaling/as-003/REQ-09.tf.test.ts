import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { As003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:scaling-events';

const ALL_EVENT_TYPES = [
  'autoscaling:EC2_INSTANCE_LAUNCH',
  'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
  'autoscaling:EC2_INSTANCE_TERMINATE',
  'autoscaling:EC2_INSTANCE_TERMINATE_ERROR',
  'autoscaling:TEST_NOTIFICATION',
];

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

function notification(notifications: string[]): TerraformResource {
  return {
    type: 'aws_autoscaling_notification',
    name: 'scaling',
    address: 'aws_autoscaling_notification.scaling',
    values: {
      group_names: [group.address],
      topic_arn: TOPIC_ARN,
      notifications,
    },
  };
}

function runControl(notifications: string[]): ScanResult | null {
  const allResources = [group, notification(notifications)];
  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources,
  };
  const adapter = new As003TfAdapterFactory().bind(context) as As003Adapter;
  return as003Control.run(adapter, context);
}

describe('AS-003 Terraform - notification configuration covering all supported event types', () => {
  // Primary behaviour owned by this requirement: a notification covering the group with
  // every supported event type satisfies AS-003.
  it('passes when the notification subscribes to all five supported event types', () => {
    expect(runControl(ALL_EVENT_TYPES)).toBeNull();
  });

  // Opposite outcome: the same notification with an SNS topic remains, but the only
  // event type is the test notification, so no real scaling event is delivered.
  it('flags when the same notification covers only the test notification', () => {
    const result = runControl(['autoscaling:TEST_NOTIFICATION']);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe(group.address);
  });
});
