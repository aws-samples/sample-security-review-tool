import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005CfnAdapterFactory();

function scan(resource: Resource) {
  const template = { Resources: { Asg: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Asg',
  };
  return as005Control.run(factory.bind(context), context);
}

function groupWithMixedInstancesPolicy(launchTemplateId: unknown): Resource {
  return {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '2',
      MixedInstancesPolicy: {
        LaunchTemplate: {
          LaunchTemplateSpecification: {
            LaunchTemplateId: launchTemplateId,
            Version: '1',
          },
        },
      },
    },
  } as unknown as Resource;
}

describe('AS-005 CloudFormation — mixed instances policy launch template identifier from a deployment-time input', () => {
  // Primary behavior owned by this requirement: a mixed instances policy can only
  // reference a launch template, so an identifier that is unresolved at scan time still passes.
  it('passes when the mixed instances policy launch template id is an unresolved cross-stack import', () => {
    const result = scan(groupWithMixedInstancesPolicy({ 'Fn::ImportValue': 'SharedLaunchTemplateId' }));

    expect(result).toBeNull();
  });

  it('passes when the mixed instances policy launch template id comes from an unresolved conditional', () => {
    const result = scan(
      groupWithMixedInstancesPolicy({ 'Fn::If': ['UseAlternate', 'lt-primary', 'lt-alternate'] }),
    );

    expect(result).toBeNull();
  });

  // Opposite outcome: the identifier is still present but names no launch template,
  // so the group is not provably launched from a launch template.
  it('flags a mixed instances policy whose launch template id is present but empty', () => {
    const result = scan(groupWithMixedInstancesPolicy('   '));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.issue).toContain('mixed instances policy');
  });
});
