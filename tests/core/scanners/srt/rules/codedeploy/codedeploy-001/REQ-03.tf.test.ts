import { describe, it, expect } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

// REQ-03 (CODEDEPLOY-001): An alarm_configuration block with enabled = true but an empty
// alarms list attaches zero CloudWatch alarms to the deployment group and must be flagged.

const factory = new Codedeploy001TfAdapterFactory();

function scan(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  return codedeploy001Control.run(factory.bind(context), context);
}

function deploymentGroup(alarmConfiguration: unknown): TerraformResource {
  return {
    type: 'aws_codedeploy_deployment_group',
    name: 'dg',
    address: 'aws_codedeploy_deployment_group.dg',
    values: {
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      service_role_arn: 'aws_iam_role.codedeploy',
      alarm_configuration: alarmConfiguration,
    },
  } as unknown as TerraformResource;
}

describe('CODEDEPLOY-001 REQ-03 (Terraform)', () => {
  it('flags a deployment group whose alarm_configuration is enabled with an empty alarms list', () => {
    const result = scan(deploymentGroup([{ enabled: true, alarms: [] }]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('aws_codedeploy_deployment_group.dg');
    expect(result?.resourceType).toBe('aws_codedeploy_deployment_group');
  });

  // Opposite outcome: same enabled block, but the alarms list actually carries an alarm.
  it('does not flag a deployment group whose enabled alarm_configuration lists an alarm', () => {
    const result = scan(deploymentGroup([{ enabled: true, alarms: ['deployment-failure-alarm'] }]));

    expect(result).toBeNull();
  });
});
