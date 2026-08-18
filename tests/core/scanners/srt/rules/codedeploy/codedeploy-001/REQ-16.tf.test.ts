import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-16 (CODEDEPLOY-001): a deployment group whose alarm monitoring enable flag comes from a
 * deployment-time input that analysis cannot resolve, while the alarm list itself is stated
 * literally with zero entries, must be flagged: an empty alarm configuration monitors nothing
 * regardless of how the enable flag resolves.
 */

const factory = new Codedeploy001TfAdapterFactory();

// A variable with no reachable default arrives carrying the unresolved marker.
const unresolvedEnabled = '__unresolved__:var.enable_deployment_alarms';

function deploymentGroup(alarms: string[]): TerraformResource {
  return {
    type: 'aws_codedeploy_deployment_group',
    name: 'app',
    address: 'aws_codedeploy_deployment_group.app',
    values: {
      app_name: 'my-application',
      deployment_group_name: 'my-group',
      service_role_arn: 'aws_iam_role.codedeploy',
      alarm_configuration: [
        {
          enabled: unresolvedEnabled,
          alarms: alarms,
        },
      ],
    },
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context);
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 REQ-16 (Terraform)', () => {
  it('flags a deployment group with an unresolved enabled flag and a literal empty alarms list', () => {
    const result = run(deploymentGroup([]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceType).toBe('aws_codedeploy_deployment_group');
    expect(result?.resourceName).toBe('aws_codedeploy_deployment_group.app');
  });

  it('flags when the literal alarms list holds only a blank alarm name', () => {
    const result = run(deploymentGroup(['  ']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
  });

  // Opposite outcome: only the alarms list contents change — one real alarm is named, so with the
  // enabled flag unresolved the configuration is not provably unmonitored and must not be flagged.
  it('does not flag when the literal alarms list names an alarm and the enabled flag is unresolved', () => {
    const result = run(deploymentGroup(['deployment-failure-alarm']));

    expect(result).toBeNull();
  });
});
