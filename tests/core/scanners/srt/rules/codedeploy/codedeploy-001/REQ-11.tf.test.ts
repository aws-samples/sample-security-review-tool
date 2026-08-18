import { describe, it, expect } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'aws_codedeploy_deployment_group';
const ADDRESS = 'aws_codedeploy_deployment_group.app';

const unresolved = (expression: string) => `__unresolved__:${expression}`;

function buildResource(values: Record<string, unknown>): TerraformResource {
  return { type: RESOURCE_TYPE, name: 'app', address: ADDRESS, values } as TerraformResource;
}

function run(values: Record<string, unknown>) {
  const resource = buildResource(values);
  const context: TfContext = { projectName: 'test-project', resource, allResources: [resource] };
  const adapter = new Codedeploy001TfAdapterFactory().bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 (Terraform) - alarm enabled flag from an unresolvable deployment-time input', () => {
  // Primary behavior owned by REQ-11: unknowable enabled flag + a named alarm => no finding.
  it('does not report a finding when enabled comes from a variable with no reachable default and one named alarm is listed', () => {
    const result = run({
      app_name: 'my-app',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [
        {
          enabled: unresolved('var.enable_deployment_alarms'),
          alarms: ['deployment-error-rate'],
        },
      ],
    });

    expect(result).toBeNull();
  });

  it('does not report a finding when enabled comes from an unresolvable local and one named alarm is listed', () => {
    const result = run({
      app_name: 'my-app',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [
        {
          enabled: unresolved('local.alarms_on'),
          alarms: ['deployment-error-rate'],
        },
      ],
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: the same named alarm, but the enabled flag is a readable "off" value.
  it('reports a finding when the enabled flag is literally false even though a named alarm is listed', () => {
    const result = run({
      app_name: 'my-app',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [
        {
          enabled: false,
          alarms: ['deployment-error-rate'],
        },
      ],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
    expect(result?.resourceName).toBe(ADDRESS);
  });
});
