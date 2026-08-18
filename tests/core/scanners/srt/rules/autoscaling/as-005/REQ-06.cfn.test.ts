import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005CfnAdapterFactory();

function buildContext(properties: Record<string, unknown>): CfnContext {
  const template = {
    Resources: {
      Asg: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: properties,
      },
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource: template.Resources!['Asg'],
    logicalId: 'Asg',
  };
}

function run(properties: Record<string, unknown>): ScanResult | null {
  const context = buildContext(properties);
  const adapter = factory.bind(context) as As005Adapter;
  return as005Control.run(adapter, context);
}

describe('AS-005 (CloudFormation) — Auto Scaling group must use a launch template', () => {
  // Primary behavior owned by REQ-06: no launch source declared at all must be flagged,
  // because EC2 Auto Scaling supplies no default launch source.
  it('flags an Auto Scaling group that declares no launch configuration, no launch template, and no mixed instances policy', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: the nearest input that flips the verdict — a launch template is present.
  it('does not flag an otherwise identical group that references a launch template', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
      LaunchTemplate: {
        LaunchTemplateId: 'LaunchTemplate',
        Version: '1',
      },
    });

    expect(result).toBeNull();
  });
});
