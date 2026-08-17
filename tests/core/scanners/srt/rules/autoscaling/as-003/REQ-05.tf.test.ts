import { describe, it, expect } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003TfAdapterFactory();

const group: TerraformResource = {
  type: 'aws_autoscaling_group',
  name: 'app',
  address: 'aws_autoscaling_group.app',
  values: {
    name: 'app-asg',
    min_size: 1,
    max_size: 3,
  },
} as TerraformResource;

function buildContext(notifications: string[]): TfContext {
  const notification: TerraformResource = {
    type: 'aws_autoscaling_notification',
    name: 'scaling',
    address: 'aws_autoscaling_notification.scaling',
    values: {
      group_names: ['aws_autoscaling_group.app'],
      topic_arn: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
      notifications,
    },
  } as TerraformResource;

  return {
    projectName: 'test-project',
    resource: group,
    allResources: [group, notification],
  };
}

function scan(context: TfContext) {
  return as003Control.run(factory.bind(context) as any, context);
}

describe('AS-003 REQ-05 (Terraform): failure-only notification event types', () => {
  // Primary behaviour owned by this requirement: launch-failure and terminate-failure
  // event types are real scaling events, so the group passes.
  it('passes when the only event types are the launch failure and terminate failure events', () => {
    const result = scan(
      buildContext([
        'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
        'autoscaling:EC2_INSTANCE_TERMINATE_ERROR',
      ]),
    );
    expect(result).toBeNull();
  });

  // Opposite outcome: identical wiring, but the only event is the test notification,
  // which delivers no real scaling event.
  it('flags when the only event is the test notification', () => {
    const result = scan(buildContext(['autoscaling:TEST_NOTIFICATION']));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
  });
});
