import { describe, it, expect } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004CfnAdapterFactory();

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;

  const template = {
    Resources: { Asg: resource },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Asg',
  };
}

function run(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  return as004Control.run(factory.bind(context), context);
}

describe('AS-004 (CloudFormation) — health check type supplied by a deployment-time value', () => {
  // REQ-15 owns this behavior: an unresolvable health check type cannot be asserted a breach.
  it('passes when the group lists a target group and HealthCheckType is an unresolved Fn::If', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '2',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc'],
      HealthCheckType: { 'Fn::If': ['UseElbHealthChecks', 'ELB', 'EC2'] },
    });

    expect(result).toBeNull();
  });

  it('passes when the group lists a target group and HealthCheckType is an unresolved Fn::ImportValue', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '2',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc'],
      HealthCheckType: { 'Fn::ImportValue': 'SharedHealthCheckType' },
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: same fixture, but the health check type is a resolved instance-status-only value.
  it('flags the group when the same fixture resolves HealthCheckType to EC2', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '2',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc'],
      HealthCheckType: 'EC2',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('Asg');
  });
});
