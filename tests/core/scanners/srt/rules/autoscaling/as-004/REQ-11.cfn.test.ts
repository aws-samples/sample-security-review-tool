import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
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
  return as004Control.run(factory.bind(context), context);
}

describe('AS-004 (CloudFormation): health check type naming multiple services including ELB', () => {
  // Primary behavior owned by REQ-11: a comma-separated list that includes ELB satisfies the rule.
  it('passes a target-group-attached group whose HealthCheckType is "EC2,ELB"', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc123'],
      HealthCheckType: 'EC2,ELB',
    });

    expect(result).toBeNull();
  });

  it('passes a target-group-attached group whose HealthCheckType lists ELB first ("ELB,EC2")', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc123'],
      HealthCheckType: 'ELB,EC2',
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: same attached group, but the list names EC2 alone, so ELB checks are off.
  it('flags the otherwise identical group whose HealthCheckType is only "EC2"', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc123'],
      HealthCheckType: 'EC2',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('Asg');
  });
});
