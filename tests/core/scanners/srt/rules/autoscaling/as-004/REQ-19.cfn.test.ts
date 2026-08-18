import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004CfnAdapterFactory();

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;
  const template = { Resources: { Asg: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: 'Asg' };
}

function run(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 CloudFormation - REQ-19: empty traffic source collection with EC2-only health checks', () => {
  // Primary behavior owned by this requirement: an unattached group may use EC2 health checks.
  it('passes when TrafficSources is an empty array and HealthCheckType is EC2', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '2',
      TrafficSources: [],
      HealthCheckType: 'EC2',
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: only the traffic source collection changes - now non-empty.
  it('flags the group when the traffic source collection is non-empty and HealthCheckType is still EC2', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '2',
      TrafficSources: [{ Identifier: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc' }],
      HealthCheckType: 'EC2',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('Asg');
  });
});
