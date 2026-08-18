import { describe, it, expect } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const ADDRESS = 'aws_codedeploy_deployment_group.example';
const RESOURCE_TYPE = 'aws_codedeploy_deployment_group';

function buildResource(values: Record<string, unknown>): TerraformResource {
  return {
    type: RESOURCE_TYPE,
    name: 'example',
    address: ADDRESS,
    values,
  } as TerraformResource;
}

function run(values: Record<string, unknown>) {
  const resource = buildResource(values);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = new Codedeploy001TfAdapterFactory().bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 (Terraform) - REQ-04: alarm configuration enabled with exactly one named alarm', () => {
  // Primary behavior owned by this requirement: enabled alarm configuration listing one named alarm passes.
  it('returns no finding when the alarm_configuration block is enabled and lists exactly one alarm name', () => {
    const result = run({
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [
        {
          enabled: true,
          alarms: ['deployment-error-rate-alarm'],
        },
      ],
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict - the alarm_configuration block
  // is still present and enabled, but lists no alarms at all.
  it('returns a finding when the enabled alarm_configuration block lists no alarms', () => {
    const result = run({
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [
        {
          enabled: true,
          alarms: [],
        },
      ],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe(ADDRESS);
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
  });
});
