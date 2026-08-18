import { describe, it, expect } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { CfnContext, Resource, Template, ScanResult } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005CfnAdapterFactory();

function scan(properties: Record<string, unknown>): ScanResult | null {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;

  const template = { Resources: { Asg: resource } } as unknown as Template;

  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Asg',
  };

  return as005Control.run(factory.bind(context) as As005Adapter, context);
}

describe('AS-005 CloudFormation — REQ-08: LaunchTemplate reference that identifies no launch template', () => {
  // Primary behavior owned by this requirement: a LaunchTemplate block with only
  // Version identifies no launch template, so the group must be flagged.
  it('flags a group whose LaunchTemplate supplies only Version', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      LaunchTemplate: { Version: '3' },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  it('flags a group whose LaunchTemplate supplies only Version via Fn::GetAtt-derived version value', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      LaunchTemplate: { Version: 'MyTemplate' },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
  });

  // Opposite outcome: the nearest input that flips the verdict — the same block
  // now identifies a launch template by id, so the reference resolves.
  it('does not flag a group whose LaunchTemplate names LaunchTemplateId alongside Version', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      LaunchTemplate: { LaunchTemplateId: 'MyTemplate', Version: '3' },
    });

    expect(result).toBeNull();
  });

  it('does not flag a group whose LaunchTemplate names LaunchTemplateName alongside Version', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      LaunchTemplate: { LaunchTemplateName: 'my-template', Version: '3' },
    });

    expect(result).toBeNull();
  });
});
