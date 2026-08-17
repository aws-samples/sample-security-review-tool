import { describe, it, expect } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

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

function testOnlyNotification(): TerraformResource {
  return {
    type: 'aws_autoscaling_notification',
    name: 'test_only',
    address: 'aws_autoscaling_notification.test_only',
    values: {
      group_names: ['aws_autoscaling_group.app'],
      topic_arn: 'aws_sns_topic.test_topic',
      notifications: ['autoscaling:TEST_NOTIFICATION'],
    },
  } as TerraformResource;
}

function secondNotification(notifications: string[]): TerraformResource {
  return {
    type: 'aws_autoscaling_notification',
    name: 'scaling',
    address: 'aws_autoscaling_notification.scaling',
    values: {
      group_names: ['aws_autoscaling_group.app'],
      topic_arn: 'aws_sns_topic.scaling_topic',
      notifications,
    },
  } as TerraformResource;
}

function run(notifications: string[]) {
  const allResources = [group, testOnlyNotification(), secondNotification(notifications)];
  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources,
  };
  return as003Control.run(factory.bind(context) as any, context);
}

describe('AS-003 (Terraform) - notification configurations deliver scaling events', () => {
  // Primary behavior owned by AS-003: a test-only notification alongside a real
  // launch/terminate notification does not remove scaling event coverage.
  it('passes when one notification is test-only and another covers launch and terminate events', () => {
    const result = run([
      'autoscaling:EC2_INSTANCE_LAUNCH',
      'autoscaling:EC2_INSTANCE_TERMINATE',
    ]);

    expect(result).toBeNull();
  });

  // Opposite outcome: same two notifications, but the second one also covers only
  // the test notification, so no real scaling event is ever delivered.
  it('flags when both notifications cover only the test notification', () => {
    const result = run(['autoscaling:TEST_NOTIFICATION']);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });
});
