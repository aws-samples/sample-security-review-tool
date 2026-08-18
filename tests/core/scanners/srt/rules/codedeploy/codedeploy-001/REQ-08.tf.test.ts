import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'aws_codedeploy_deployment_group';
const ADDRESS = 'aws_codedeploy_deployment_group.main';
const PROJECT_NAME = 'test-project';

function deploymentGroup(enabled: unknown): TerraformResource {
  return {
    type: RESOURCE_TYPE,
    name: 'main',
    address: ADDRESS,
    values: {
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [
        {
          alarms: ['DeploymentErrorRateAlarm'],
          enabled,
        },
      ],
    },
  } as unknown as TerraformResource;
}

function runControl(resource: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: PROJECT_NAME,
    resource,
    allResources: [resource],
  };
  const factory = new Codedeploy001TfAdapterFactory();
  expect(factory.appliesTo(RESOURCE_TYPE)).toBe(true);
  const adapter = factory.bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 (Terraform) - alarm configuration explicitly disabled', () => {
  // Primary behaviour owned by this requirement: an alarm is named but the
  // alarm_configuration block is switched off, so it is never evaluated.
  it('flags a deployment group whose alarm_configuration names an alarm but is disabled', () => {
    const result = runControl(deploymentGroup(false));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
    expect(result?.resourceName).toBe(ADDRESS);
  });

  // Opposite outcome: identical fixture with enabled = true, so the named alarm
  // really does monitor deployments.
  it('does not flag the same deployment group when alarm_configuration is enabled', () => {
    const result = runControl(deploymentGroup(true));

    expect(result).toBeNull();
  });
});
