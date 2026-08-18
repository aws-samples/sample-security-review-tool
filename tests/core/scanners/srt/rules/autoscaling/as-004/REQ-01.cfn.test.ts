import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AppAsg';

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;

  const template = {
    Resources: {
      [LOGICAL_ID]: resource,
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
}

function run(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = new As004CfnAdapterFactory().bind(context);
  return as004Control.run(adapter, context);
}

describe('AS-004 CloudFormation — REQ-01: classic load balancer attachment with EC2-only health checks', () => {
  // Primary behavior owned by this requirement: attached to a classic load
  // balancer while health check type is EC2 instance status only -> flag.
  it('flags a group that lists a classic load balancer name and uses HealthCheckType EC2', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      LoadBalancerNames: ['my-classic-lb'],
      HealthCheckType: 'EC2',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: only the health check type flips to ELB, the load
  // balancer attachment is unchanged.
  it('does not flag the same classic-load-balancer group when HealthCheckType is ELB', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      LoadBalancerNames: ['my-classic-lb'],
      HealthCheckType: 'ELB',
    });

    expect(result).toBeNull();
  });
});
