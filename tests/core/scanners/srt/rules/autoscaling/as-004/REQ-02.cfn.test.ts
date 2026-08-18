import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AppAsg';
const factory = new As004CfnAdapterFactory();

function buildGroup(properties: Record<string, unknown>): Resource {
  return {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;
}

function scan(resource: Resource): ScanResult | null {
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 CloudFormation — group attached to a target group with EC2-only health checks', () => {
  it('applies to Auto Scaling groups', () => {
    expect(factory.appliesTo('AWS::AutoScaling::AutoScalingGroup')).toBe(true);
  });

  // Primary behavior owned by this requirement: one target group listed + HealthCheckType EC2 => flag
  it('flags a group that lists one target group and uses EC2 instance status health checks only', () => {
    const result = scan(buildGroup({
      MinSize: '1',
      MaxSize: '3',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app/abc123'],
      HealthCheckType: 'EC2',
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
    expect(result?.issue).toContain('EC2 instance status');
  });

  // Opposite outcome: identical group except Elastic Load Balancing health checks are enabled
  it('does not flag the same group when the health check type is ELB', () => {
    const result = scan(buildGroup({
      MinSize: '1',
      MaxSize: '3',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app/abc123'],
      HealthCheckType: 'ELB',
    }));

    expect(result).toBeNull();
  });
});
