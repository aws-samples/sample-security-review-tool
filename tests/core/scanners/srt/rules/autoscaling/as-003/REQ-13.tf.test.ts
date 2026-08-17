import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { As003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const unresolved = (ref: string): string => `__unresolved__:${ref}`;

const factory = new As003TfAdapterFactory();

function group(): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: {
      name: 'app-asg',
      min_size: 1,
      max_size: 3,
    },
  } as TerraformResource;
}

function notification(groupNames: unknown): TerraformResource {
  return {
    type: 'aws_autoscaling_notification',
    name: 'scaling',
    address: 'aws_autoscaling_notification.scaling',
    values: {
      group_names: groupNames,
      topic_arn: 'aws_sns_topic.alerts',
      notifications: ['autoscaling:TEST_NOTIFICATION'],
    },
  } as TerraformResource;
}

function scan(resources: TerraformResource[], target: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'as-003-req-13',
    resource: target,
    allResources: resources,
  };
  const adapter = factory.bind(context) as As003Adapter;
  return as003Control.run(adapter, context);
}

describe('AS-003 Terraform - notification target group supplied by a deployment-time input', () => {
  // Primary behaviour owned by this requirement: an unresolvable group name means
  // the scanner cannot establish that this Auto Scaling group lacks notifications.
  it('does not flag the Auto Scaling group when the notification group name list is an unresolved variable reference', () => {
    const asg = group();
    const resources = [asg, notification([unresolved('var.asg_name')])];

    expect(scan(resources, asg)).toBeNull();
  });

  it('does not flag the Auto Scaling group when group_names itself is an unresolved variable reference', () => {
    const asg = group();
    const resources = [asg, notification(unresolved('var.asg_names'))];

    expect(scan(resources, asg)).toBeNull();
  });

  // Opposite outcome: identical notification, but the target group name resolves to
  // this Auto Scaling group, so the test-notification-only coverage is now provable.
  it('flags the Auto Scaling group when the resolved group name identifies it and only the test notification is delivered', () => {
    const asg = group();
    const resources = [asg, notification(['aws_autoscaling_group.app'])];

    const result = scan(resources, asg);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });
});
