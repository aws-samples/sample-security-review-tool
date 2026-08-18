import { describe, it, expect } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codedeploy001CfnAdapterFactory();

function evaluate(properties: Record<string, unknown>) {
  const resource = {
    Type: 'AWS::CodeDeploy::DeploymentGroup',
    Properties: properties,
  } as unknown as Resource;

  const template = { Resources: { DeploymentGroup: resource } } as unknown as Template;

  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'DeploymentGroup',
  };

  return codedeploy001Control.run(factory.bind(context), context);
}

describe('CODEDEPLOY-001 REQ-09 (CloudFormation): alarm configuration listing an alarm with no on/off setting', () => {
  // Primary behavior owned by this requirement: an AlarmConfiguration that names an
  // alarm but omits Enabled has no documented flag making monitoring active, so the
  // deployment group cannot be credited with alarm-based monitoring.
  it('flags a deployment group whose AlarmConfiguration lists one named alarm without Enabled', () => {
    const result = evaluate({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Alarms: [{ Name: 'deployment-errors' }],
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('DeploymentGroup');
    expect(result?.resourceType).toBe('AWS::CodeDeploy::DeploymentGroup');
  });

  // Opposite outcome: identical fixture except the on/off flag is present and on,
  // which documents monitoring as active and must not be flagged.
  it('does not flag the same deployment group when Enabled is explicitly true', () => {
    const result = evaluate({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: true,
        Alarms: [{ Name: 'deployment-errors' }],
      },
    });

    expect(result).toBeNull();
  });
});
