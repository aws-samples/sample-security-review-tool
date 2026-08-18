import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'AWS::CodeDeploy::DeploymentGroup';
const LOGICAL_ID = 'DeploymentGroup';
const STACK_NAME = 'test-stack';

function buildTemplate(resource: Resource): Template {
  return { Resources: { [LOGICAL_ID]: resource } } as Template;
}

function runControl(resource: Resource): ScanResult | null {
  const template = buildTemplate(resource);
  const context: CfnContext = {
    stackName: STACK_NAME,
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
  const factory = new Codedeploy001CfnAdapterFactory();
  expect(factory.appliesTo(RESOURCE_TYPE)).toBe(true);
  const adapter = factory.bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

function deploymentGroup(alarmConfiguration: Record<string, unknown>): Resource {
  return {
    Type: RESOURCE_TYPE,
    Properties: {
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: alarmConfiguration,
    },
  } as unknown as Resource;
}

describe('CODEDEPLOY-001 (CloudFormation) - alarm configuration explicitly disabled', () => {
  // Primary behaviour owned by this requirement: an alarm is named but the
  // alarm configuration is switched off, so CodeDeploy never evaluates it.
  it('flags a deployment group whose alarm configuration names an alarm but is disabled', () => {
    const result = runControl(deploymentGroup({
      Enabled: false,
      Alarms: [{ Name: 'DeploymentErrorRateAlarm' }],
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
    expect(result?.resourceName).toBe(LOGICAL_ID);
  });

  // Opposite outcome: identical fixture with the configuration enabled, so the
  // named alarm really does monitor deployments.
  it('does not flag the same deployment group when the alarm configuration is enabled', () => {
    const result = runControl(deploymentGroup({
      Enabled: true,
      Alarms: [{ Name: 'DeploymentErrorRateAlarm' }],
    }));

    expect(result).toBeNull();
  });
});
