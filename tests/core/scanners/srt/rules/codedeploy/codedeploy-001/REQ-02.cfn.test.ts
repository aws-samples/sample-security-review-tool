import { describe, it, expect } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { CfnContext, Resource, Template, ScanResult } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'AWS::CodeDeploy::DeploymentGroup';
const LOGICAL_ID = 'DeploymentGroup';

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

function run(properties: Record<string, unknown>): ScanResult | null {
  const context = buildContext(properties);
  const factory = new Codedeploy001CfnAdapterFactory();
  expect(factory.appliesTo(RESOURCE_TYPE)).toBe(true);
  const adapter = factory.bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 REQ-02 (CloudFormation): AlarmConfiguration block with no properties', () => {
  // Primary behavior owned by this requirement: an empty AlarmConfiguration block
  // supplies no Alarms and leaves alarm monitoring disabled, so it must be flagged.
  it('flags a deployment group whose AlarmConfiguration block is empty', () => {
    const result = run({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      DeploymentGroupName: 'my-deployment-group',
      AlarmConfiguration: {},
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
  });

  // Opposite outcome: nearest input that flips the verdict — the same AlarmConfiguration
  // block, present, but carrying one CloudWatch alarm entry.
  it('does not flag a deployment group whose AlarmConfiguration block lists one alarm', () => {
    const result = run({
      ApplicationName: 'my-app',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      DeploymentGroupName: 'my-deployment-group',
      AlarmConfiguration: {
        Enabled: true,
        Alarms: [{ Name: 'my-deployment-alarm' }],
      },
    });

    expect(result).toBeNull();
  });
});
