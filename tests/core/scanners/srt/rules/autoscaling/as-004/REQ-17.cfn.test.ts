import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'WebAsg';

function buildTemplate(healthCheckType: string): Template {
  return {
    Resources: {
      [LOGICAL_ID]: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '3',
          TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web/abc123'],
          HealthCheckType: healthCheckType,
        },
      },
    },
  } as unknown as Template;
}

function run(healthCheckType: string) {
  const template = buildTemplate(healthCheckType);
  const resource = (template.Resources as Record<string, Resource>)[LOGICAL_ID];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
  const adapter = new As004CfnAdapterFactory().bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 CloudFormation - health check type token casing (REQ-17)', () => {
  // Primary behaviour owned by this requirement: lower-case "elb" is not the
  // recognised ELB token, so a target-group-attached group is flagged.
  it('flags a target-group-attached group whose HealthCheckType is lower-case "elb"', () => {
    const result = run('elb');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: same fixture, only the casing of the token changes.
  it('does not flag the same group when HealthCheckType is the exact token "ELB"', () => {
    expect(run('ELB')).toBeNull();
  });
});
