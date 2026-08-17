import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003CfnAdapterFactory();

function buildContext(asgProperties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: asgProperties,
  } as unknown as Resource;

  const template = {
    Resources: {
      Asg: resource,
      ScalingTopic: { Type: 'AWS::SNS::Topic', Properties: {} },
    },
  } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId: 'Asg' };
}

function run(asgProperties: Record<string, unknown>) {
  const context = buildContext(asgProperties);
  return as003Control.run(factory.bind(context), context);
}

describe('AS-003 REQ-01 (CloudFormation): notification configuration must be present on Auto Scaling groups', () => {
  // Primary behavior owned by this requirement: the property is omitted entirely -> flag.
  it('flags an Auto Scaling group whose NotificationConfigurations property is omitted entirely', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: same group, notification configuration supplied -> no finding.
  it('does not flag an Auto Scaling group that declares a notification configuration for launch, terminate and failure events', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
      NotificationConfigurations: [
        {
          TopicARN: { Ref: 'ScalingTopic' },
          NotificationTypes: [
            'autoscaling:EC2_INSTANCE_LAUNCH',
            'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
            'autoscaling:EC2_INSTANCE_TERMINATE',
            'autoscaling:EC2_INSTANCE_TERMINATE_ERROR',
          ],
        },
      ],
    });

    expect(result).toBeNull();
  });
});
