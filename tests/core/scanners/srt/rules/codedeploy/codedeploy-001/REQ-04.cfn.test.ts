import { describe, it, expect } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'DeploymentGroup';
const RESOURCE_TYPE = 'AWS::CodeDeploy::DeploymentGroup';

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: RESOURCE_TYPE,
    Properties: properties,
  } as unknown as Resource;

  const template = {
    Resources: {
      [LOGICAL_ID]: resource,
    },
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

describe('CODEDEPLOY-001 (CloudFormation) - REQ-04: alarm configuration enabled with exactly one named alarm', () => {
  // Primary behavior owned by this requirement: enabled alarm configuration listing one named alarm passes.
  it('returns no finding when the alarm configuration is enabled and lists exactly one named alarm', () => {
    const result = run({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: true,
        Alarms: [{ Name: 'deployment-error-rate-alarm' }],
      },
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict - the alarm configuration is
  // still present and enabled, but lists no alarms at all.
  it('returns a finding when the enabled alarm configuration lists no alarms', () => {
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
