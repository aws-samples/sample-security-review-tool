import { describe, it, expect } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'WebAsg';

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function scan(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = new As004CfnAdapterFactory().bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

const TWO_TARGET_GROUPS = [
  'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-blue/0123456789abcdef',
  'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-green/abcdef0123456789',
];

describe('AS-004 (CloudFormation) - multiple target groups with EC2-only health checks', () => {
  // Primary behavior owned by AS-004: attached to load balancing yet EC2-only health checks.
  it('flags a group listing more than one target group when HealthCheckType is EC2', () => {
    const result = scan({
      MinSize: '2',
      MaxSize: '6',
      TargetGroupARNs: TWO_TARGET_GROUPS,
      HealthCheckType: 'EC2',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: same multi-target-group attachment, but ELB health checks are enabled.
  it('does not flag the same group when HealthCheckType is ELB', () => {
    const result = scan({
      MinSize: '2',
      MaxSize: '6',
      TargetGroupARNs: TWO_TARGET_GROUPS,
      HealthCheckType: 'ELB',
    });

    expect(result).toBeNull();
  });
});
