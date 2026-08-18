import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'Asg';
const RESOURCE_TYPE = 'AWS::AutoScaling::AutoScalingGroup';

function evaluateGroup(properties: Record<string, unknown>): ScanResult | null {
  const resource = { Type: RESOURCE_TYPE, Properties: properties } as unknown as Resource;
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
  const adapter = new As005CfnAdapterFactory().bind(context) as As005Adapter;
  return as005Control.run(adapter, context);
}

describe('AS-005 (CloudFormation): mixed instances policy without any launch template specification', () => {
  // Primary behaviour owned by AS-005: a mixed instances policy that supplies no launch
  // template specification supplies no launch template at all, so the group must be flagged.
  it('flags a group whose mixed instances policy contains no launch template specification', () => {
    const result = evaluateGroup({
      MinSize: '1',
      MaxSize: '3',
      MixedInstancesPolicy: {
        InstancesDistribution: {
          OnDemandBaseCapacity: 1,
          SpotAllocationStrategy: 'capacity-optimized',
        },
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
  });

  it('flags a group whose mixed instances policy has a launch template block with an empty specification', () => {
    const result = evaluateGroup({
      MinSize: '1',
      MaxSize: '3',
      MixedInstancesPolicy: {
        LaunchTemplate: {
          Overrides: [{ InstanceType: 'm5.large' }],
        },
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
  });

  // Opposite outcome: identical group except the mixed instances policy does name a launch
  // template, which is exactly what the requirement turns on.
  it('does not flag a group whose mixed instances policy names a launch template', () => {
    const result = evaluateGroup({
      MinSize: '1',
      MaxSize: '3',
      MixedInstancesPolicy: {
        InstancesDistribution: {
          OnDemandBaseCapacity: 1,
          SpotAllocationStrategy: 'capacity-optimized',
        },
        LaunchTemplate: {
          LaunchTemplateSpecification: {
            LaunchTemplateId: 'LaunchTemplate',
            Version: '1',
          },
        },
      },
    });

    expect(result).toBeNull();
  });
});
