import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AppAsg';

function buildTemplate(groupProperties: Record<string, unknown>): Template {
  return {
    Resources: {
      AppTargetGroup: {
        Type: 'AWS::ElasticLoadBalancingV2::TargetGroup',
        Properties: { Port: 80, Protocol: 'HTTP', VpcId: 'vpc-0123456789abcdef0' },
      } as unknown as Resource,
      [LOGICAL_ID]: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: groupProperties,
      } as unknown as Resource,
    },
  } as unknown as Template;
}

function run(groupProperties: Record<string, unknown>): ScanResult | null {
  const template = buildTemplate(groupProperties);
  const resource = (template.Resources as Record<string, Resource>)[LOGICAL_ID];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
  const factory = new As004CfnAdapterFactory();
  expect(factory.appliesTo(resource.Type)).toBe(true);
  return as004Control.run(factory.bind(context), context);
}

/**
 * REQ-03 owns this behavior: a group wired to a target group through a traffic
 * source, whose health check type is EC2 instance status only, must be flagged.
 */
describe('AS-004 REQ-03 (CloudFormation): traffic source attachment with EC2-only health checks', () => {
  it('flags a group with a target group traffic source and HealthCheckType EC2', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      TrafficSources: [{ Identifier: 'AppTargetGroup', Type: 'elbv2' }],
      HealthCheckType: 'EC2',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
    expect(result?.issue).toMatch(/EC2 instance status/i);
  });

  // Opposite outcome: identical traffic source attachment, but the health check
  // type meets the standard (ELB), so there is nothing to flag.
  it('does not flag the same traffic source attachment when HealthCheckType is ELB', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      TrafficSources: [{ Identifier: 'AppTargetGroup', Type: 'elbv2' }],
      HealthCheckType: 'ELB',
    });

    expect(result).toBeNull();
  });
});
