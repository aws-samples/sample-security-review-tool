import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004CfnAdapterFactory();

function buildGroup(properties: Record<string, unknown>): Resource {
  return {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;
}

function evaluate(resource: Resource): ScanResult | null {
  const template = {
    Resources: { Asg: resource },
  } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Asg',
  };
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 CloudFormation — group attached to a target group', () => {
  // Primary behavior owned by REQ-09: ELB health checks on an attached group pass.
  it('passes when the group lists a target group and its health check type is ELB', () => {
    const result = evaluate(buildGroup({
      MinSize: '1',
      MaxSize: '3',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app/abc123'],
      HealthCheckType: 'ELB',
    }));

    expect(result).toBeNull();
  });

  // Opposite outcome: only the health check type changes to instance-status-only.
  it('flags the same group when its health check type is EC2 instead of ELB', () => {
    const result = evaluate(buildGroup({
      MinSize: '1',
      MaxSize: '3',
      TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app/abc123'],
      HealthCheckType: 'EC2',
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });
});
