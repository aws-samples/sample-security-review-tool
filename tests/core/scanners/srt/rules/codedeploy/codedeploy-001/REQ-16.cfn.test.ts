import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-16 (CODEDEPLOY-001): a deployment group whose alarm monitoring enable flag comes from a
 * deployment-time input that analysis cannot resolve, while the alarm list itself is stated
 * literally with zero entries, must be flagged: an empty alarm configuration monitors nothing
 * regardless of how the enable flag resolves.
 */

const factory = new Codedeploy001CfnAdapterFactory();

function buildContext(resource: Resource, logicalId = 'DeploymentGroup'): CfnContext {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId };
}

function run(resource: Resource) {
  const context = buildContext(resource);
  const adapter = factory.bind(context);
  return codedeploy001Control.run(adapter, context);
}

// The unresolvable enable flag: Fn::If survives preprocessing as an opaque object.
const unresolvableEnabled = { 'Fn::If': ['EnableAlarms', true, false] };

function deploymentGroup(alarms: unknown[]): Resource {
  return {
    Type: 'AWS::CodeDeploy::DeploymentGroup',
    Properties: {
      ApplicationName: 'MyApplication',
      ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      AlarmConfiguration: {
        Enabled: unresolvableEnabled,
        Alarms: alarms,
      },
    },
  } as unknown as Resource;
}

describe('CODEDEPLOY-001 REQ-16 (CloudFormation)', () => {
  it('flags a deployment group with an unresolvable Enabled flag and a literal empty alarm list', () => {
    const result = run(deploymentGroup([]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceType).toBe('AWS::CodeDeploy::DeploymentGroup');
    expect(result?.resourceName).toBe('DeploymentGroup');
  });

  it('flags when the literal alarm list holds only an entry that names no alarm', () => {
    const result = run(deploymentGroup([{ Name: '   ' }]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
  });

  // Opposite outcome: only the alarm list contents change — one real alarm is named, so with the
  // enable flag unresolvable the configuration is not provably unmonitored and must not be flagged.
  it('does not flag when the literal alarm list names an alarm and the Enabled flag is unresolvable', () => {
    const result = run(deploymentGroup([{ Name: 'DeploymentFailureAlarm' }]));

    expect(result).toBeNull();
  });
});
