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

function scan(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 CloudFormation — target group attached group with empty health check type', () => {
  // Primary behavior owned by AS-004: an empty HealthCheckType names no ELB
  // health check, so an ASG with a target group runs on EC2 status checks alone.
  it('flags a group that lists a target group and sets HealthCheckType to an empty string', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '3',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app/0123456789abcdef'],
      HealthCheckType: '',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  it('does not flag the same group when the health check type names ELB instead of being empty', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '3',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app/0123456789abcdef'],
      HealthCheckType: 'ELB',
    });

    expect(result).toBeNull();
  });
});
