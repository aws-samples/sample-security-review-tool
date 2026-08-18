import { describe, it, expect } from 'vitest';
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

  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function run(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = new Codedeploy001CfnAdapterFactory().bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 (CloudFormation) - alarm Enabled flag from an unresolvable deployment-time input', () => {
  // Primary behavior owned by REQ-11: unknowable Enabled flag + a named alarm => no finding.
  it('does not report a finding when Enabled is an unresolved intrinsic and one named alarm is listed', () => {
    const result = run({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        // Fn::If is not resolved by preprocessing - the real value is only known at deploy time.
        Enabled: { 'Fn::If': ['EnableAlarms', true, false] },
        Alarms: [{ Name: 'deployment-error-rate' }],
      },
    });

    expect(result).toBeNull();
  });

  it('does not report a finding when Enabled comes from an unresolved cross-stack import and one named alarm is listed', () => {
    const result = run({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: { 'Fn::ImportValue': 'SharedAlarmToggle' },
        Alarms: [{ Name: 'deployment-error-rate' }],
      },
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: the same named alarm, but the Enabled flag is a readable "off" value.
  it('reports a finding when the Enabled flag resolves to false even though a named alarm is listed', () => {
    const result = run({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: false,
        Alarms: [{ Name: 'deployment-error-rate' }],
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
    expect(result?.resourceName).toBe(LOGICAL_ID);
  });
});
