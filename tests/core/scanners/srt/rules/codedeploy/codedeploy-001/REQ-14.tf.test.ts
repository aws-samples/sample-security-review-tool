import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'aws_codedeploy_deployment_group';
const ADDRESS = 'aws_codedeploy_deployment_group.group';

function buildResource(values: Record<string, unknown>): TerraformResource {
  return { type: RESOURCE_TYPE, name: 'group', address: ADDRESS, values } as TerraformResource;
}

function scan(values: Record<string, unknown>) {
  const resource = buildResource(values);
  const context: TfContext = { projectName: 'test-project', resource, allResources: [resource] };
  const adapter = new Codedeploy001TfAdapterFactory().bind(context);
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 (Terraform) — enabled alarm_configuration whose only alarm entry has no name', () => {
  // Primary behaviour owned by CODEDEPLOY-001: the sole alarm entry names no alarm,
  // so the enabled alarm configuration watches nothing.
  it('flags a deployment group whose enabled alarm list holds one nameless entry', () => {
    const result = scan({
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [{ enabled: true, alarms: [''] }],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe(ADDRESS);
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
  });

  // Opposite outcome: identical fixture except the single alarm entry names an alarm.
  it('does not flag when the single alarm entry names a CloudWatch alarm', () => {
    const result = scan({
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [{ enabled: true, alarms: ['deployment-error-rate'] }],
    });

    expect(result).toBeNull();
  });
});
