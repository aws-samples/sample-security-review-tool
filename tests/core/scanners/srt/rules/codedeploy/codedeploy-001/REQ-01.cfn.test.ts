import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codedeploy001CfnAdapterFactory();

function runControl(logicalId: string, resource: Resource) {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  return codedeploy001Control.run(factory.bind(context), context);
}

// REQ-01 (primary): a deployment group with no alarm configuration of any kind must be flagged.
describe('CODEDEPLOY-001 CloudFormation: deployment group without alarm monitoring', () => {
  it('flags a deployment group defined with application, service role and deployment style but no alarm configuration', () => {
    const resource = {
      Type: 'AWS::CodeDeploy::DeploymentGroup',
      Properties: {
        ApplicationName: 'MyApplication',
        ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
        DeploymentGroupName: 'MyDeploymentGroup',
        DeploymentStyle: {
          DeploymentType: 'BLUE_GREEN',
          DeploymentOption: 'WITH_TRAFFIC_CONTROL',
        },
      },
    } as unknown as Resource;

    const result = runControl('UnmonitoredDeploymentGroup', resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('UnmonitoredDeploymentGroup');
    expect(result?.resourceType).toBe('AWS::CodeDeploy::DeploymentGroup');
  });

  // Opposite outcome: identical group, but with one CloudWatch alarm configured — must NOT be flagged.
  it('does not flag an otherwise identical deployment group that lists one CloudWatch alarm', () => {
    const resource = {
      Type: 'AWS::CodeDeploy::DeploymentGroup',
      Properties: {
        ApplicationName: 'MyApplication',
        ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
        DeploymentGroupName: 'MyDeploymentGroup',
        DeploymentStyle: {
          DeploymentType: 'BLUE_GREEN',
          DeploymentOption: 'WITH_TRAFFIC_CONTROL',
        },
        AlarmConfiguration: {
          Enabled: true,
          Alarms: [{ Name: 'DeploymentErrorRateAlarm' }],
        },
      },
    } as unknown as Resource;

    const result = runControl('MonitoredDeploymentGroup', resource);

    expect(result).toBeNull();
  });
});
