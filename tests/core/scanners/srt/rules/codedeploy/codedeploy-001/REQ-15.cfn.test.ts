import { describe, it, expect } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codedeploy001CfnAdapterFactory();

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::CodeDeploy::DeploymentGroup',
    Properties: properties,
  } as unknown as Resource;

  const template = {
    Resources: { DeploymentGroup: resource },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'DeploymentGroup',
  };
}

function scan(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = factory.bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 REQ-15 (CloudFormation): enabled alarm configuration with one unresolvable alarm name', () => {
  // Primary behaviour owned by REQ-15: an enabled AlarmConfiguration listing one alarm
  // counts as monitored even when the alarm name is a deployment-time value that
  // preprocessing cannot resolve (here an Fn::ImportValue that stays an object).
  it('passes when the single listed alarm name is an unresolved intrinsic', () => {
    const result = scan({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: true,
        Alarms: [{ Name: { 'Fn::ImportValue': 'SharedAlarmName' } }],
      },
    });

    expect(result).toBeNull();
  });

  it('passes when the alarm name comes from an unresolved Fn::If', () => {
    const result = scan({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: true,
        Alarms: [{ Name: { 'Fn::If': ['UseProdAlarm', 'prod-alarm', 'dev-alarm'] } }],
      },
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: same enabled configuration with one entry, but the name is
  // present-and-empty, so it identifies no alarm at all and must be flagged.
  it('flags a deployment group whose single listed alarm has a blank name', () => {
    const result = scan({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: true,
        Alarms: [{ Name: '   ' }],
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('DeploymentGroup');
    expect(result?.resourceType).toBe('AWS::CodeDeploy::DeploymentGroup');
  });
});
