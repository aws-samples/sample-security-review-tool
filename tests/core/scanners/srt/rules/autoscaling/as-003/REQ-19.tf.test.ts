import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003TfAdapterFactory();

/** A var reference with no reachable default arrives marked unresolved. */
const unresolved = (expression: string) => `__unresolved__:${expression}`;

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
      group_names: ['aws_autoscaling_group.app'],
      // Destination topic comes from a deployment-time input that analysis cannot resolve.
      topic_arn: unresolved('var.scaling_topic_arn'),
      notifications,
    },
  };
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

describe('AS-003 Terraform - notification configuration must deliver real scaling events', () => {
  // Primary behaviour owned by AS-003: only the test notification is listed, so no
  // launch, terminate, or failure event is ever delivered, whatever the topic resolves to.
  it('flags a group whose only notification is autoscaling:TEST_NOTIFICATION with an unresolvable topic', () => {
    const result = scan(notification(['autoscaling:TEST_NOTIFICATION']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: identical fixture, unresolvable topic unchanged, but the
  // notifications list now includes a real scaling event - nothing to flag.
  it('does not flag a group whose notifications include a real scaling event with the same unresolvable topic', () => {
    const result = scan(notification(['autoscaling:EC2_INSTANCE_LAUNCH', 'autoscaling:TEST_NOTIFICATION']));

    expect(result).toBeNull();
  });
});
