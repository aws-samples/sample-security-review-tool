import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'AWS::CodeDeploy::DeploymentGroup';
const LOGICAL_ID = 'DeploymentGroup';

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = { Type: RESOURCE_TYPE, Properties: properties } as unknown as Resource;
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function scan(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = new Codedeploy001CfnAdapterFactory().bind(context);
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 (CloudFormation) — enabled alarm configuration whose only alarm entry has no name', () => {
  // Primary behaviour owned by CODEDEPLOY-001: an enabled alarm configuration whose
  // single alarm entry carries no Name identifies zero real CloudWatch alarms.
  it('flags a deployment group whose enabled alarm list holds one entry with no Name', () => {
    const result = scan({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: true,
        Alarms: [{}],
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
  });

  // Opposite outcome: identical fixture except the single alarm entry names an alarm.
  it('does not flag when the single alarm entry names a CloudWatch alarm', () => {
    const result = scan({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: true,
        Alarms: [{ Name: 'deployment-error-rate' }],
      },
    });

    expect(result).toBeNull();
  });
});
