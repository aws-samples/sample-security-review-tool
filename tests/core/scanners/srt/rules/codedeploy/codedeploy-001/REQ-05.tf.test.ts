import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'aws_codedeploy_deployment_group';
const ADDRESS = 'aws_codedeploy_deployment_group.dg';

function buildResource(values: Record<string, unknown>): TerraformResource {
  return {
    type: RESOURCE_TYPE,
    name: 'dg',
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

describe('CODEDEPLOY-001 Terraform — alarm monitoring enabled with named alarms', () => {
  // Primary behaviour owned by this requirement: an enabled alarm_configuration
  // block listing several named alarms satisfies the rule.
  it('passes when alarm_configuration is enabled and lists several named alarms', () => {
    const result = run({
      app_name: 'my-app',
      deployment_group_name: 'my-dg',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [
        {
          enabled: true,
          alarms: ['deployment-error-rate', 'deployment-latency', 'deployment-5xx'],
        },
      ],
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: the alarm_configuration block is still present and enabled,
  // but the alarms list is empty, so no alarm is actually monitored.
  it('flags when alarm_configuration is enabled but the alarms list is empty', () => {
    const result = run({
      app_name: 'my-app',
      deployment_group_name: 'my-dg',
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
