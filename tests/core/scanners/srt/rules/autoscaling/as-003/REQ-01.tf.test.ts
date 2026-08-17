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
    min_size: 1,
    max_size: 3,
    launch_template: [{ id: 'aws_launch_template.lt' }],
  },
} as unknown as TerraformResource;

function run(allResources: TerraformResource[]) {
  const context: TfContext = { projectName: 'test-project', resource: asg, allResources };
  return as003Control.run(factory.bind(context), context);
}

describe('AS-003 REQ-01 (Terraform): notification configuration must be present for Auto Scaling groups', () => {
  // Primary behavior owned by this requirement: no notification configuration exists at all -> flag.
  it('flags an Auto Scaling group with no notification configuration in the project', () => {
    const result = run([asg]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: same group, an aws_autoscaling_notification wired to it -> no finding.
  it('does not flag an Auto Scaling group covered by an aws_autoscaling_notification for launch, terminate and failure events', () => {
    const notification: TerraformResource = {
      type: 'aws_autoscaling_notification',
      name: 'scaling',
      address: 'aws_autoscaling_notification.scaling',
      values: {
        group_names: ['aws_autoscaling_group.app'],
        topic_arn: 'aws_sns_topic.scaling',
        notifications: [
          'autoscaling:EC2_INSTANCE_LAUNCH',
          'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
          'autoscaling:EC2_INSTANCE_TERMINATE',
          'autoscaling:EC2_INSTANCE_TERMINATE_ERROR',
        ],
      },
    } as unknown as TerraformResource;

    const result = run([asg, notification]);

    expect(result).toBeNull();
  });
});
