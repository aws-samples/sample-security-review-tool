import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'Asg';

function runControl(resource: Record<string, unknown>): ScanResult | null {
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resource as unknown as Resource,
    logicalId: LOGICAL_ID,
  };
  const adapter = new As005CfnAdapterFactory().bind(context) as As005Adapter;
  return as005Control.run(adapter, context);
}

describe('AS-005 CloudFormation — REQ-02: launch template referenced by id plus version, no launch configuration', () => {
  // Primary behaviour owned by this requirement: a complete LaunchTemplateSpecification
  // (LaunchTemplateId + Version) with no launch configuration is compliant.
  it('does not flag an Auto Scaling group whose LaunchTemplate gives LaunchTemplateId and Version', () => {
    const result = runControl({
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      Properties: {
        MinSize: '1',
        MaxSize: '3',
        LaunchTemplate: {
          LaunchTemplateId: 'LaunchTemplate',
          Version: 'LaunchTemplate',
        },
      },
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: same group, but its instance configuration comes from a
  // launch configuration instead of a launch template.
  it('flags an Auto Scaling group that names a launch configuration instead of a launch template', () => {
    const result = runControl({
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      Properties: {
        MinSize: '1',
        MaxSize: '3',
        LaunchConfigurationName: 'LaunchConfig',
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });
});
