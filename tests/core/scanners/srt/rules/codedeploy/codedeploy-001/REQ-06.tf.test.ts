import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codedeploy001TfAdapterFactory();

function deploymentGroup(alarms: unknown[]): TerraformResource {
  return {
    type: 'aws_codedeploy_deployment_group',
    name: 'dg',
    address: 'aws_codedeploy_deployment_group.dg',
    values: {
      app_name: 'my-app',
      deployment_group_name: 'my-dg',
      service_role_arn: 'aws_iam_role.codedeploy',
      alarm_configuration: [
        {
          enabled: true,
          alarms: alarms,
        },
      ],
    },
  } as unknown as TerraformResource;
}

function evaluate(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context);
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 (Terraform) REQ-06: enabled alarm_configuration whose only alarm name is an empty string', () => {
  // Primary behavior owned by this requirement: an empty alarm name identifies no CloudWatch alarm,
  // so the enabled alarm configuration monitors nothing and must be flagged.
  it('flags a deployment group whose single alarm name is an empty string', () => {
    const result = evaluate(deploymentGroup(['']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('aws_codedeploy_deployment_group.dg');
    expect(result?.resourceType).toBe('aws_codedeploy_deployment_group');
  });

  // Opposite outcome: identical fixture except the alarm entry carries a real alarm name.
  it('does not flag a deployment group whose single alarm name is non-empty', () => {
    const result = evaluate(deploymentGroup(['deployment-errors-alarm']));

    expect(result).toBeNull();
  });
});
