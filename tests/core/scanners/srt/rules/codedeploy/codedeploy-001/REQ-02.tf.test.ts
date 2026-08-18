import { describe, it, expect } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { TfContext, TerraformResource, ScanResult } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

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

function run(values: Record<string, unknown>): ScanResult | null {
  const resource = buildResource(values);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const factory = new Codedeploy001TfAdapterFactory();
  expect(factory.appliesTo(RESOURCE_TYPE)).toBe(true);
  const adapter = factory.bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 REQ-02 (Terraform): alarm_configuration block with no arguments', () => {
  // Primary behavior owned by this requirement: an alarm_configuration block written
  // with no arguments lists no alarms, so alarm monitoring is effectively disabled.
  it('flags a deployment group whose alarm_configuration block is empty', () => {
    const result = run({
      app_name: 'my-app',
      deployment_group_name: 'my-deployment-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [{}],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe(ADDRESS);
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
  });

  // Opposite outcome: nearest input that flips the verdict — the same block, present,
  // but carrying one alarm name.
  it('does not flag a deployment group whose alarm_configuration block lists one alarm', () => {
    const result = run({
      app_name: 'my-app',
      deployment_group_name: 'my-deployment-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [{ enabled: true, alarms: ['my-deployment-alarm'] }],
    });

    expect(result).toBeNull();
  });
});
