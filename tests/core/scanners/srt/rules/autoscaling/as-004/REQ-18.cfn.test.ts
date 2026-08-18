import { describe, expect, it } from 'vitest';

import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'Asg';

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;

  const template = {
    Resources: { [LOGICAL_ID]: resource },
  } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function scan(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = new As004CfnAdapterFactory().bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 (CloudFormation): unattached group with Elastic Load Balancing health checks', () => {
  // Primary behavior owned by this requirement: out of scope because nothing is attached.
  it('passes a group with no load balancer, target group, or traffic source and HealthCheckType ELB', () => {
        const result = scan({
      MinSize: '1',
      MaxSize: '2',
      HealthCheckType: 'ELB',
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: the nearest input that brings the group into scope with EC2-only health checks.
  it('flags a group attached to a target group whose HealthCheckType is EC2', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc'],
      HealthCheckType: 'EC2',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe(LOGICAL_ID);
  });
});
