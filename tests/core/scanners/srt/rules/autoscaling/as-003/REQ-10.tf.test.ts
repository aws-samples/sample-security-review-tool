import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { As003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003TfAdapterFactory();

function scan(topicArn: unknown): ScanResult | null {
  const group: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: { name: 'app-asg', min_size: 1, max_size: 2 },
  } as TerraformResource;

  const notification: TerraformResource = {
    type: 'aws_autoscaling_notification',
    name: 'app',
    address: 'aws_autoscaling_notification.app',
    values: {
      group_names: ['aws_autoscaling_group.app'],
      notifications: [
        'autoscaling:EC2_INSTANCE_LAUNCH',
        'autoscaling:EC2_INSTANCE_TERMINATE',
      ],
      topic_arn: topicArn,
    },
  } as TerraformResource;

  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources: [group, notification],
  };

  const adapter = factory.bind(context) as As003Adapter;
  return as003Control.run(adapter, context);
}

describe('AS-003 Terraform - notification with an empty destination topic identifier', () => {
  // Primary behavior owned by this requirement: an empty topic_arn names no SNS
  // topic, so launch/terminate notifications cannot be delivered -> flag.
  it('flags an Auto Scaling group whose covering notification has an empty topic_arn', () => {
    const result = scan('');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  it('flags an Auto Scaling group whose covering notification topic_arn is only whitespace', () => {
    const result = scan('   ');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
  });

  // Opposite outcome: identical wiring but topic_arn references a real SNS topic
  // resource, so the notifications can be delivered -> no finding.
  it('does not flag the same wiring when topic_arn references a real SNS topic', () => {
    const result = scan('aws_sns_topic.scaling');

    expect(result).toBeNull();
  });
});
