import { describe, it, expect } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003CfnAdapterFactory();

function buildContext(notificationTypes: string[]): CfnContext {
  const template = {
    Resources: {
      Asg: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '3',
          AvailabilityZones: ['us-east-1a'],
          NotificationConfigurations: [
            {
              TopicARN: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
              NotificationTypes: notificationTypes,
            },
          ],
        },
      },
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, any>)['Asg'],
    logicalId: 'Asg',
  };
}

function scan(context: CfnContext) {
  return as003Control.run(factory.bind(context) as any, context);
}

describe('AS-003 REQ-05 (CloudFormation): failure-only notification event types', () => {
  // Primary behaviour owned by this requirement: launch-failure and terminate-failure
  // event types are real scaling events, so the group passes.
  it('passes when the only event types are the launch failure and terminate failure events', () => {
    const result = scan(
      buildContext([
        'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
        'autoscaling:EC2_INSTANCE_TERMINATE_ERROR',
      ]),
    );
    expect(result).toBeNull();
  });

  // Opposite outcome: same notification configuration shape, but the only event type
  // is the test notification, which delivers no real scaling event.
  it('flags when the only event type is the test notification', () => {
    const result = scan(buildContext(['autoscaling:TEST_NOTIFICATION']));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
  });
});
