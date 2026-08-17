import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003CfnAdapterFactory();

function scan(resource: Resource, logicalId = 'AppAsg'): ScanResult | null {
  const template = {
    Resources: { [logicalId]: resource },
  } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  return as003Control.run(factory.bind(context), context);
}

function group(notificationConfigurations: unknown): Resource {
  return {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
      LaunchConfigurationName: 'AppLaunchConfig',
      NotificationConfigurations: notificationConfigurations,
    },
  } as unknown as Resource;
}

describe('AS-003 CloudFormation - empty notification configuration collection', () => {
  // Primary behavior owned by this requirement: an empty collection means no
  // notification target exists, so the group must be flagged.
  it('flags an Auto Scaling group whose NotificationConfigurations list is declared but empty', () => {
    const result = scan(group([]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
    expect(result?.resourceName).toBe('AppAsg');
  });

  // Opposite outcome: identical group, but the collection contains one real entry.
  it('does not flag an Auto Scaling group whose NotificationConfigurations list contains a real scaling event entry', () => {
    const result = scan(
      group([
        {
          TopicARN: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
          NotificationTypes: [
            'autoscaling:EC2_INSTANCE_LAUNCH',
            'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
            'autoscaling:EC2_INSTANCE_TERMINATE',
            'autoscaling:EC2_INSTANCE_TERMINATE_ERROR',
          ],
        },
      ]),
    );

    expect(result).toBeNull();
  });
});
