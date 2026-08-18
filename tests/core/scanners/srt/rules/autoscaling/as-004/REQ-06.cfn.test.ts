import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004CfnAdapterFactory();

function scan(resource: Resource): ReturnType<typeof as004Control.run> {
  const template = { Resources: { Asg: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Asg',
  };
  return as004Control.run(factory.bind(context), context);
}

describe('AS-004 CloudFormation — attachment list known only at deployment time', () => {
  // REQ-06 owns this behaviour: the target group list is unresolvable, so the
  // rule cannot assert that the group is attached to a load balancer at all.
  it('passes when TargetGroupARNs comes entirely from an unresolved intrinsic and health checks are EC2 only', () => {
    const result = scan({
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      Properties: {
        MinSize: '1',
        MaxSize: '2',
        HealthCheckType: 'EC2',
        // Post-preprocessing shape: Fn::Select/Fn::Split over an import stays an object.
        TargetGroupARNs: {
          'Fn::Split': [',', { 'Fn::ImportValue': 'SharedTargetGroupArns' }],
        },
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });

  it('passes when TargetGroupARNs is an unresolved Fn::If and health checks are EC2 only', () => {
    const result = scan({
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      Properties: {
        MinSize: '1',
        MaxSize: '2',
        HealthCheckType: 'EC2',
        TargetGroupARNs: {
          'Fn::If': ['AttachTargetGroup', ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc'], []],
        },
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict — the same group with a
  // resolved, non-empty target group list. Primary behaviour belongs to the base rule.
  it('flags the same group when TargetGroupARNs resolves to a concrete non-empty list with EC2-only health checks', () => {
    const result = scan({
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      Properties: {
        MinSize: '1',
        MaxSize: '2',
        HealthCheckType: 'EC2',
        TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc'],
      },
    } as unknown as Resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('Asg');
  });
});
