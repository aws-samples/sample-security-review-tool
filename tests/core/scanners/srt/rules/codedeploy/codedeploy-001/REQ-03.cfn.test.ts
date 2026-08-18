import { describe, it, expect } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

// REQ-03 (CODEDEPLOY-001): A deployment group whose AlarmConfiguration is enabled but
// whose Alarms list is empty has zero CloudWatch alarms attached and must be flagged.

const factory = new Codedeploy001CfnAdapterFactory();

function scan(resource: Resource, logicalId = 'DeploymentGroup') {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  return codedeploy001Control.run(factory.bind(context), context);
}

function deploymentGroup(alarmConfiguration: unknown): Resource {
  return {
    Type: 'AWS::CodeDeploy::DeploymentGroup',
    Properties: {
      ApplicationName: 'MyApp',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: alarmConfiguration,
    },
  } as unknown as Resource;
}

describe('CODEDEPLOY-001 REQ-03 (CloudFormation)', () => {
  it('flags a deployment group whose alarm configuration is enabled with an empty alarm list', () => {
    const result = scan(deploymentGroup({ Enabled: true, Alarms: [] }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('DeploymentGroup');
    expect(result?.resourceType).toBe('AWS::CodeDeploy::DeploymentGroup');
  });

  // Opposite outcome: same enabled configuration, but the alarm list actually carries an alarm.
  it('does not flag a deployment group whose enabled alarm configuration lists an alarm', () => {
    const result = scan(deploymentGroup({ Enabled: true, Alarms: [{ Name: 'DeploymentFailureAlarm' }] }));

    expect(result).toBeNull();
  });
});
