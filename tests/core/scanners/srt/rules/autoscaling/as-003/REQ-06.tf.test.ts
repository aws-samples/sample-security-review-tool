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
    launch_template: [{ id: 'aws_launch_template.lt' }],
  },
} as TerraformResource;

function buildContext(notifications: string[]): TfContext {
  const notification: TerraformResource = {
    type: 'aws_autoscaling_notification',
    name: 'scaling',
    address: 'aws_autoscaling_notification.scaling',
    values: {
      group_names: ['aws_autoscaling_group.app'],
      topic_arn: 'aws_sns_topic.scaling',
      notifications,
    },
  } as TerraformResource;

  return { projectName: 'test-project', resource: group, allResources: [group, notification] };
}

function scan(context: TfContext) {
  return as003Control.run(factory.bind(context), context);
}

describe('AS-003 REQ-06 (Terraform): notification configuration with an empty event-type list', () => {
  // Primary behavior owned by this requirement: an empty notifications list
  // subscribes the topic to no scaling events, so the group must be flagged.
  it('flags an Auto Scaling group whose notification resource lists no event types', () => {
    const result = scan(buildContext([]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: the nearest input that flips the verdict - the same
  // notification resource with a real scaling event present in the list.
  it('does not flag an Auto Scaling group whose notification resource lists a real scaling event', () => {
    const result = scan(buildContext(['autoscaling:EC2_INSTANCE_LAUNCH']));

    expect(result).toBeNull();
  });
});
