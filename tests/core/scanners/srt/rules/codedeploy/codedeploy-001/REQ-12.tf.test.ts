import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'aws_codedeploy_deployment_group';
const ADDRESS = 'aws_codedeploy_deployment_group.app';

function unresolved(reference: string): string {
  return `__unresolved__:${reference}`;
}

function buildResource(values: Record<string, unknown>): TerraformResource {
  return {
    type: RESOURCE_TYPE,
    name: 'app',
    address: ADDRESS,
    values,
  } as TerraformResource;
}

function scan(values: Record<string, unknown>) {
  const resource = buildResource(values);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = new Codedeploy001TfAdapterFactory().bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 (Terraform) - alarm list supplied by an unresolvable deployment-time input', () => {
  // Primary behavior owned by this requirement: an alarm list the scanner cannot
  // resolve may well contain at least one alarm, so no finding is raised.
  it('does not flag a deployment group whose alarms come from a variable with no reachable default', () => {
    const result = scan({
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      alarm_configuration: [
        {
          enabled: true,
          alarms: unresolved('var.alarm_names'),
        },
      ],
    });

    expect(result).toBeNull();
  });

  it('does not flag a deployment group whose alarms come from a local value', () => {
    const result = scan({
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      alarm_configuration: [
        {
          enabled: true,
          alarms: unresolved('local.deployment_alarms'),
        },
      ],
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: identical fixture except the alarm list is resolvable and
  // contains no alarms, which the rule must flag.
  it('flags a deployment group whose resolvable alarm list is empty', () => {
    const result = scan({
      app_name: 'my-app',
      deployment_group_name: 'my-group',
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
