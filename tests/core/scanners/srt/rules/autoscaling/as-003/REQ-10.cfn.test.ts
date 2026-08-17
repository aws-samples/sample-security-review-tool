import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { As003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003CfnAdapterFactory();

function scan(topicArn: unknown): ScanResult | null {
  const template = {
    Resources: {
      Asg: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '2',
          NotificationConfigurations: [
            {
              TopicARN: topicArn,
              NotificationTypes: [
                'autoscaling:EC2_INSTANCE_LAUNCH',
                'autoscaling:EC2_INSTANCE_TERMINATE',
              ],
            },
          ],
        },
      },
    },
  } as unknown as Template;

  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, never>)['Asg'],
    logicalId: 'Asg',
  };

  const adapter = factory.bind(context) as As003Adapter;
  return as003Control.run(adapter, context);
}

describe('AS-003 CloudFormation - notification configuration with an empty destination topic identifier', () => {
  // Primary behavior owned by this requirement: an empty TopicARN names no SNS
  // topic, so launch/terminate notifications cannot be delivered -> flag.
  it('flags an Auto Scaling group whose notification configuration has an empty TopicARN', () => {
    const result = scan('');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  it('flags an Auto Scaling group whose notification configuration TopicARN is only whitespace', () => {
    const result = scan('   ');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
  });

  // Opposite outcome: identical configuration but the destination topic is a real
  // ARN, so the launch/terminate notifications can be delivered -> no finding.
  it('does not flag the same configuration when the TopicARN names a real SNS topic', () => {
    const result = scan('arn:aws:sns:us-east-1:123456789012:scaling-events');

    expect(result).toBeNull();
  });
});
