import { describe, it, expect } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codedeploy001TfAdapterFactory();

function evaluate(values: Record<string, unknown>) {
  const resource: TerraformResource = {
    type: 'aws_codedeploy_deployment_group',
    name: 'group',
    address: 'aws_codedeploy_deployment_group.group',
    values,
  } as TerraformResource;

  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };

  return codedeploy001Control.run(factory.bind(context), context);
}

describe('CODEDEPLOY-001 REQ-09 (Terraform): alarm_configuration listing an alarm with no on/off setting', () => {
  // Primary behavior owned by this requirement: an alarm_configuration block naming
  // an alarm but omitting `enabled` has no documented flag making monitoring active.
  it('flags a deployment group whose alarm_configuration lists one named alarm without enabled', () => {
    const result = evaluate({
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [{ alarms: ['deployment-errors'] }],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('aws_codedeploy_deployment_group.group');
    expect(result?.resourceType).toBe('aws_codedeploy_deployment_group');
  });

  // Opposite outcome: identical fixture except the on/off flag is present and on.
  it('does not flag the same deployment group when enabled is explicitly true', () => {
    const result = evaluate({
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [{ enabled: true, alarms: ['deployment-errors'] }],
    });

    expect(result).toBeNull();
  });
});
