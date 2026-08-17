import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003TfAdapterFactory();

const unresolved = (ref: string): string => `__unresolved__:${ref}`;

const group: TerraformResource = {
  type: 'aws_autoscaling_group',
  name: 'app',
  address: 'aws_autoscaling_group.app',
  values: {
    name: 'app-asg',
    min_size: 1,
    max_size: 3,
  },
} as unknown as TerraformResource;

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
  } as unknown as TerraformResource;
}

function scan(notificationResource: TerraformResource): ScanResult | null {
  const allResources = [group, notificationResource];
  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources,
  };
  return as003Control.run(factory.bind(context), context);
}

describe('AS-003 REQ-08 (Terraform): notification event type must be a recognized Auto Scaling event type', () => {
  it('flags an Auto Scaling group whose notification event type is not a recognized Auto Scaling event type', () => {
    const result = scan(notification(['autoscaling:EC2_INSTANCE_REBOOT']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });

  it('flags a group whose notification event types are all unrecognized strings', () => {
    const result = scan(notification(['EC2_INSTANCE_LAUNCH', 'autoscaling:SCALING_ACTIVITY']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
  });

  // Opposite outcome: same wiring, recognized event type. Primary behavior for
  // the "recognized event type is present" case belongs to the base AS-003
  // requirement; asserted here only to prove this file discriminates.
  it('does not flag an Auto Scaling group whose notification event type is a recognized Auto Scaling event type', () => {
    const result = scan(notification(['autoscaling:EC2_INSTANCE_LAUNCH']));

    expect(result).toBeNull();
  });

  it('does not flag when the event type comes from an unresolved variable reference', () => {
    const result = scan(notification([unresolved('var.notification_types')]));

    expect(result).toBeNull();
  });
});
