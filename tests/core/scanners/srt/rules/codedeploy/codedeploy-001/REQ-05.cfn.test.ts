import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'AWS::CodeDeploy::DeploymentGroup';
const LOGICAL_ID = 'DeploymentGroup';

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: RESOURCE_TYPE,
    Properties: properties,
  } as unknown as Resource;

  const template = {
    Resources: { [LOGICAL_ID]: resource },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
}

function run(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = new Codedeploy001CfnAdapterFactory().bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 CloudFormation — alarm monitoring enabled with named alarms', () => {
  // Primary behaviour owned by this requirement: enabled alarm configuration
  // listing several named alarms is exactly the state the rule requires.
  it('passes when AlarmConfiguration is enabled and lists several named alarms', () => {
    const result = run({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: true,
        Alarms: [
          { Name: 'deployment-error-rate' },
          { Name: 'deployment-latency' },
          { Name: 'deployment-5xx' },
        ],
      },
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: the alarm configuration is still present and switched on,
  // but the Alarms list is empty, so nothing is actually monitored.
  it('flags when AlarmConfiguration is enabled but the Alarms list is empty', () => {
    const result = run({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: true,
        Alarms: [],
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
  });
});
