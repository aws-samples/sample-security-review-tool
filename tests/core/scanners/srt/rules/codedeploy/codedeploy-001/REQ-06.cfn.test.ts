import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codedeploy001CfnAdapterFactory();

function buildContext(resource: Resource): CfnContext {
  const template = { Resources: { DeploymentGroup: resource } } as unknown as Template;
  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'DeploymentGroup',
  };
}

function evaluate(resource: Resource) {
  const context = buildContext(resource);
  const adapter = factory.bind(context);
  return codedeploy001Control.run(adapter, context);
}

function deploymentGroup(alarms: unknown[]): Resource {
  return {
    Type: 'AWS::CodeDeploy::DeploymentGroup',
    Properties: {
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: true,
        Alarms: alarms,
      },
    },
  } as unknown as Resource;
}

describe('CODEDEPLOY-001 (CloudFormation) REQ-06: enabled alarm configuration whose only alarm entry has an empty name', () => {
  // Primary behavior owned by this requirement: an empty Name identifies no CloudWatch alarm,
  // so the enabled alarm configuration monitors nothing and must be flagged.
  it('flags a deployment group whose single alarm entry has an empty Name', () => {
    const result = evaluate(deploymentGroup([{ Name: '' }]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('DeploymentGroup');
    expect(result?.resourceType).toBe('AWS::CodeDeploy::DeploymentGroup');
  });

  // Opposite outcome: identical fixture except the alarm entry carries a real alarm name.
  it('does not flag a deployment group whose single alarm entry has a non-empty Name', () => {
    const result = evaluate(deploymentGroup([{ Name: 'deployment-errors-alarm' }]));

    expect(result).toBeNull();
  });
});
