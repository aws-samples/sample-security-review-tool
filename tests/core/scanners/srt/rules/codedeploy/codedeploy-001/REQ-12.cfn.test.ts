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

  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
}

function scan(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = new Codedeploy001CfnAdapterFactory().bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 (CloudFormation) - alarm list supplied by an unresolvable deployment-time input', () => {
  // Primary behavior owned by this requirement: an alarm list the scanner cannot
  // resolve may well contain at least one alarm, so no finding is raised.
  it('does not flag a deployment group whose alarm list stays an unresolved intrinsic', () => {
    const result = scan({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: true,
        Alarms: {
          'Fn::If': ['UseProvidedAlarms', [{ Name: 'DeploymentErrors' }], [{ Name: 'Deployment5xx' }]],
        },
      },
    });

    expect(result).toBeNull();
  });

  it('does not flag a deployment group whose alarm list comes from a cross-stack import', () => {
    const result = scan({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: true,
        Alarms: { 'Fn::ImportValue': 'SharedAlarmList' },
      },
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: identical fixture except the alarm list is resolvable and
  // contains no alarms, which the rule must flag.
  it('flags a deployment group whose resolvable alarm list is empty', () => {
    const result = scan({
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
