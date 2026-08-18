import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codedeploy001CfnAdapterFactory();

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::CodeDeploy::DeploymentGroup',
    Properties: {
      ApplicationName: 'MyApplication',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      ...properties,
    },
  } as unknown as Resource;

  const template = { Resources: { DeploymentGroup: resource } } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'DeploymentGroup',
  };
}

function run(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  return codedeploy001Control.run(factory.bind(context), context);
}

describe('CODEDEPLOY-001 REQ-10 (CloudFormation): alarm configuration explicitly disabled with no alarms listed', () => {
  // Primary behavior owned by this requirement: Enabled false + empty alarm list means no monitoring exists.
  it('flags a deployment group whose AlarmConfiguration is disabled and lists no alarms', () => {
    const result = run({
      AlarmConfiguration: {
        Enabled: false,
        Alarms: [],
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('DeploymentGroup');
    expect(result?.resourceType).toBe('AWS::CodeDeploy::DeploymentGroup');
  });

  // Opposite outcome: same shape, but monitoring is switched on and an alarm is actually named.
  it('does not flag a deployment group whose AlarmConfiguration is enabled and lists an alarm', () => {
    const result = run({
      AlarmConfiguration: {
        Enabled: true,
        Alarms: [{ Name: 'deployment-error-rate' }],
      },
    });

    expect(result).toBeNull();
  });
});
