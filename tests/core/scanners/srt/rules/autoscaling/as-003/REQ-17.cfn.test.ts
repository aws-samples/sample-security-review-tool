import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { As003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LAUNCH_AND_TERMINATE = [
  'autoscaling:EC2_INSTANCE_LAUNCH',
  'autoscaling:EC2_INSTANCE_TERMINATE',
];

function buildContext(notificationConfigurations: unknown): CfnContext {
  const group = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
      LaunchConfigurationName: 'AppLaunchConfig',
      NotificationConfigurations: notificationConfigurations,
    },
  } as unknown as Resource;

  const template = { Resources: { AppGroup: group } } as unknown as Template;

  return { stackName: 'test-stack', template, resource: group, logicalId: 'AppGroup' };
}

function run(notificationConfigurations: unknown): ScanResult | null {
  const context = buildContext(notificationConfigurations);
  const adapter = new As003CfnAdapterFactory().bind(context) as As003Adapter;
  return as003Control.run(adapter, context);
}

describe('AS-003 (CloudFormation) - notification configuration must name a destination topic', () => {
  // Primary behavior owned by this requirement: event types listed, but no TopicARN at all.
  it('flags an Auto Scaling group whose notification configuration lists launch and terminate events with no TopicARN', () => {
    const result = run([{ NotificationTypes: LAUNCH_AND_TERMINATE }]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('AppGroup');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
    expect(result?.issue).toMatch(/topic/i);
  });

  // Opposite outcome: same event types, but a destination topic is named.
  it('does not flag the same notification configuration when a destination TopicARN is named', () => {
    const result = run([
      {
        TopicARN: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
        NotificationTypes: LAUNCH_AND_TERMINATE,
      },
    ]);

    expect(result).toBeNull();
  });
});
