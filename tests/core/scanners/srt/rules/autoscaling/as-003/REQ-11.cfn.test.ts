import { describe, it, expect } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { As003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AppAsg';
const factory = new As003CfnAdapterFactory();

function contextFor(resource: Resource): CfnContext {
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function scan(resource: Resource) {
  const ctx = contextFor(resource);
  const adapter = factory.bind(ctx) as As003Adapter;
  return as003Control.run(adapter, ctx);
}

function group(notificationTypes: unknown): Resource {
  return {
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
}

describe('AS-003 CloudFormation - notification event types supplied by an unresolvable deployment-time input', () => {
  // Primary behavior owned by this requirement: event types that cannot be resolved
  // at analysis time must not be reported as a breach.
  it('does not flag when the event type list is an unresolved Fn::Split over a deployment-time input', () => {
    const resource = group({ 'Fn::Split': [',', { 'Fn::ImportValue': 'ScalingEventTypes' }] });

    expect(scan(resource)).toBeNull();
  });

  it('does not flag when the event type list is an unresolved Fn::If', () => {
    const resource = group({
      'Fn::If': [
        'IncludeFailures',
        ['autoscaling:EC2_INSTANCE_LAUNCH_ERROR'],
        ['autoscaling:EC2_INSTANCE_LAUNCH'],
      ],
    });

    expect(scan(resource)).toBeNull();
  });

  // Opposite outcome: same fixture, but the event types are resolvable and cover no
  // real scaling event, so the rule must report a finding.
  it('flags when the resolved event type list covers only the test notification', () => {
    const resource = group(['autoscaling:TEST_NOTIFICATION']);

    const result = scan(resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe(LOGICAL_ID);
  });
});
