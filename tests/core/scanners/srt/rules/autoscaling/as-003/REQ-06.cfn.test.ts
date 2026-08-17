import { describe, it, expect } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003CfnAdapterFactory();

function buildContext(notificationTypes: string[]): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '3',
      NotificationConfigurations: [
        {
          TopicARN: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
          NotificationTypes: notificationTypes,
        },
      ],
    },
  } as unknown as Resource;

  const template = { Resources: { Asg: resource } } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId: 'Asg' };
}

function scan(context: CfnContext) {
  return as003Control.run(factory.bind(context), context);
}

describe('AS-003 REQ-06 (CloudFormation): notification configuration with an empty event-type list', () => {
  // Primary behavior owned by this requirement: an empty NotificationTypes list
  // subscribes the topic to no scaling events, so the group must be flagged.
  it('flags an Auto Scaling group whose notification configuration lists no event types', () => {
    const result = scan(buildContext([]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: the nearest input that flips the verdict - the same
  // configuration with a real scaling event present in the list.
  it('does not flag an Auto Scaling group whose notification configuration lists a real scaling event', () => {
    const result = scan(buildContext(['autoscaling:EC2_INSTANCE_LAUNCH']));

    expect(result).toBeNull();
  });
});
