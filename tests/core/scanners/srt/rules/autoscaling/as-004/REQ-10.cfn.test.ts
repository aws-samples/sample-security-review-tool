import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
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
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 CloudFormation — target group attached with health check type omitted (REQ-10)', () => {
  // Primary behavior owned by this requirement: TargetGroupARNs present and HealthCheckType absent
  // defaults to EC2 status checks only, so the group must be flagged.
  it('flags a group that lists a target group and specifies no HealthCheckType', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app/abc123'],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: only the health check type changes — it is present and set to ELB.
  it('does not flag the same group when HealthCheckType is set to ELB', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app/abc123'],
      HealthCheckType: 'ELB',
    });

    expect(result).toBeNull();
  });
});
