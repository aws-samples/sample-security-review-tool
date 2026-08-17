import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003TfAdapterFactory();

const asg: TerraformResource = {
  type: 'aws_autoscaling_group',
  name: 'app',
  address: 'aws_autoscaling_group.app',
  values: {
    name: 'app-asg',
    min_size: 1,
    max_size: 3,
    launch_template: [{ id: 'aws_launch_template.app' }],
  },
} as unknown as TerraformResource;

function notification(groupNames: unknown): TerraformResource {
  return {
    type: 'aws_autoscaling_notification',
    name: 'scaling_events',
    address: 'aws_autoscaling_notification.scaling_events',
    values: {
      group_names: groupNames,
      notifications: [
        'autoscaling:EC2_INSTANCE_LAUNCH',
        'autoscaling:EC2_INSTANCE_TERMINATE',
      ],
      topic_arn: 'aws_sns_topic.scaling_events',
    },
  } as unknown as TerraformResource;
}

function run(resources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: asg,
    allResources: [asg, ...resources],
  };
  return as003Control.run(factory.bind(context), context);
}

describe('AS-003 REQ-02 (Terraform): notification configuration for scaling events', () => {
  // Primary behavior owned by AS-003: launch + terminate coverage satisfies the rule.
  it('passes when a notification resource covers the group with launch and terminate events', () => {
    const result = run([notification(['aws_autoscaling_group.app'])]);

    expect(result).toBeNull();
  });

  it('passes when the notification references the group by its literal name', () => {
    const result = run([notification(['app-asg'])]);

    expect(result).toBeNull();
  });

  it('flags the group when the launch/terminate notification covers a different group', () => {
    const result = run([notification(['aws_autoscaling_group.other'])]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });
});
