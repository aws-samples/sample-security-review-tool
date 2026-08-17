import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003CfnAdapterFactory();

const NOTIFICATION_CONFIGURATIONS = [
  {
    TopicARN: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
    NotificationTypes: [
      'autoscaling:EC2_INSTANCE_LAUNCH',
      'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
      'autoscaling:EC2_INSTANCE_TERMINATE',
      'autoscaling:EC2_INSTANCE_TERMINATE_ERROR',
    ],
  },
];

function group(properties: Record<string, unknown>): Resource {
  return {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
      ...properties,
    },
  } as unknown as Resource;
}

function buildTemplate(assessedProperties: Record<string, unknown>): Template {
  return {
    Resources: {
      // Assessed group
      AssessedGroup: group(assessedProperties),
      // A different group that does carry a scaling-event notification configuration
      OtherGroup: group({ NotificationConfigurations: NOTIFICATION_CONFIGURATIONS }),
    },
  } as unknown as Template;
}

function run(template: Template, logicalId: string) {
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, Resource>)[logicalId],
    logicalId,
  };
  return as003Control.run(factory.bind(context), context);
}

describe('AS-003 CloudFormation - notification configuration scoped to another Auto Scaling group', () => {
  // Primary behavior owned by this requirement: another group's notification
  // configuration does not cover the assessed group, so the assessed group is flagged.
  it('flags the assessed group when only a different group in the template has NotificationConfigurations', () => {
    const result = run(buildTemplate({}), 'AssessedGroup');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('AssessedGroup');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: identical template, except the assessed group carries its own
  // notification configuration - the verdict flips to no finding.
  it('does not flag the assessed group when it has its own NotificationConfigurations', () => {
    const result = run(
      buildTemplate({ NotificationConfigurations: NOTIFICATION_CONFIGURATIONS }),
      'AssessedGroup',
    );

    expect(result).toBeNull();
  });

  it('does not flag the other group that owns the notification configuration', () => {
    const result = run(buildTemplate({}), 'OtherGroup');

    expect(result).toBeNull();
  });
});
