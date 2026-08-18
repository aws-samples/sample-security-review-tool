import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codedeploy001TfAdapterFactory();

function buildResource(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_codedeploy_deployment_group',
    name: 'app',
    address: 'aws_codedeploy_deployment_group.app',
    values: {
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      ...values,
    },
  } as TerraformResource;
}

function run(values: Record<string, unknown>) {
  const resource = buildResource(values);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  return codedeploy001Control.run(factory.bind(context), context);
}

describe('CODEDEPLOY-001 REQ-10 (Terraform): alarm configuration explicitly disabled with no alarms listed', () => {
  // Primary behavior owned by this requirement: enabled = false + empty alarms means no monitoring exists.
  it('flags a deployment group whose alarm_configuration is disabled and lists no alarms', () => {
    const result = run({
      alarm_configuration: [{ enabled: false, alarms: [] }],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('aws_codedeploy_deployment_group.app');
    expect(result?.resourceType).toBe('aws_codedeploy_deployment_group');
  });

  // Opposite outcome: same shape, but monitoring is switched on and an alarm is actually named.
  it('does not flag a deployment group whose alarm_configuration is enabled and lists an alarm', () => {
    const result = run({
      alarm_configuration: [{ enabled: true, alarms: ['deployment-error-rate'] }],
    });

    expect(result).toBeNull();
  });
});
