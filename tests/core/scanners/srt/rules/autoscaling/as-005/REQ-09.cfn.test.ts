import { describe, expect, it } from 'vitest';

import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'Asg';
const STACK_NAME = 'test-stack';

function scan(properties: Record<string, unknown>): ScanResult | null {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  const context: CfnContext = { stackName: STACK_NAME, template, resource, logicalId: LOGICAL_ID };
  const adapter = new As005CfnAdapterFactory().bind(context) as As005Adapter;
  return as005Control.run(adapter, context);
}

function mixedPolicyProperties(specification: Record<string, unknown>): Record<string, unknown> {
  return {
    MinSize: '1',
    MaxSize: '2',
    MixedInstancesPolicy: {
      LaunchTemplate: {
        LaunchTemplateSpecification: specification,
      },
    },
  };
}

describe('AS-005 (CloudFormation) mixed instances policy launch template reference', () => {
  // Primary behavior owned by REQ-09: a mixed instances policy launch template
  // reference that supplies only a version identifies no launch template at all.
  it('flags a group whose mixed instances policy launch template specification supplies only a Version', () => {
    const result = scan(mixedPolicyProperties({ Version: '3' }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: the nearest input that flips the verdict — the same
  // specification, still carrying the Version, but now naming a launch template.
  it('does not flag a group whose mixed instances policy launch template specification names a launch template alongside the Version', () => {
    const result = scan(mixedPolicyProperties({ LaunchTemplateId: 'lt-0123456789abcdef0', Version: '3' }));

    expect(result).toBeNull();
  });
});
