import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AppAsg';

function scan(properties: Record<string, unknown>): ScanResult | null {
  const template = {
    Resources: {
      [LOGICAL_ID]: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: properties,
      },
    },
  } as unknown as Template;

  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: template.Resources![LOGICAL_ID],
    logicalId: LOGICAL_ID,
  };

  const factory = new As004CfnAdapterFactory();
  expect(factory.appliesTo('AWS::AutoScaling::AutoScalingGroup')).toBe(true);
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 CloudFormation — REQ-05: no load balancer or target group attached', () => {
  // Primary behavior owned by this requirement: empty attachment collections mean
  // ELB health checks are not applicable, so EC2-only health checks pass.
  it('passes an Auto Scaling group with empty LoadBalancerNames and empty TargetGroupARNs using EC2 health checks', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '3',
      LoadBalancerNames: [],
      TargetGroupARNs: [],
      HealthCheckType: 'EC2',
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: the only change is that one collection is non-empty, so a
  // load balancer IS attached and EC2-only health checks must be flagged.
  it('flags the otherwise identical group when LoadBalancerNames contains an entry', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '3',
      LoadBalancerNames: ['app-classic-elb'],
      TargetGroupARNs: [],
      HealthCheckType: 'EC2',
    });

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('AS-004');
    expect(result!.resourceName).toBe(LOGICAL_ID);
    expect(result!.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });
});
