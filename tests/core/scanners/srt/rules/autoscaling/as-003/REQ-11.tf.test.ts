import { describe, it, expect } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { As003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003TfAdapterFactory();

function unresolved(ref: string): string {
  return `__unresolved__:${ref}`;
}

const asg: TerraformResource = {
  type: 'aws_autoscaling_group',
  name: 'app',
  address: 'aws_autoscaling_group.app',
  values: { name: 'app-asg', min_size: 1, max_size: 3 },
};

function notification(notifications: unknown): TerraformResource {
  return {
    type: 'aws_autoscaling_notification',
    name: 'scaling',
    address: 'aws_autoscaling_notification.scaling',
    values: {
      group_names: ['aws_autoscaling_group.app'],
      topic_arn: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
      notifications,
    },
  };
}

function scan(notifications: unknown) {
  const allResources = [asg, notification(notifications)];
  const ctx: TfContext = { projectName: 'test-project', resource: asg, allResources };
  const adapter = factory.bind(ctx) as As003Adapter;
  return as003Control.run(adapter, ctx);
}

describe('AS-003 Terraform - notification event types supplied by an unresolvable deployment-time input', () => {
  // Primary behavior owned by this requirement: event types that cannot be resolved
  // at analysis time must not be reported as a breach.
  it('does not flag when notifications is a var reference with no reachable default', () => {
    expect(scan(unresolved('var.scaling_event_types'))).toBeNull();
  });

  it('does not flag when the notifications list holds only unresolved entries', () => {
    expect(scan([unresolved('local.scaling_event_types')])).toBeNull();
  });

  // Opposite outcome: same fixture, but the event types are resolvable and cover no
  // real scaling event, so the rule must report a finding.
  it('flags when the resolved notifications list covers only the test notification', () => {
    const result = scan(['autoscaling:TEST_NOTIFICATION']);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });
});
