import { describe, it, expect } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codedeploy001TfAdapterFactory();

const unresolved = (expression: string): string => `__unresolved__:${expression}`;

function buildResource(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_codedeploy_deployment_group',
    name: 'group',
    address: 'aws_codedeploy_deployment_group.group',
    values,
  } as unknown as TerraformResource;
}

function scan(values: Record<string, unknown>) {
  const resource = buildResource(values);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 REQ-15 (Terraform): enabled alarm configuration with one unresolvable alarm name', () => {
  // Primary behaviour owned by REQ-15: alarm_configuration is enabled and lists a single
  // alarm whose name is a variable with no reachable default, so the name arrives
  // unresolved. The group is still monitored by one alarm, so no finding.
  it('passes when the single listed alarm name is an unresolved variable reference', () => {
    const result = scan({
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [
        {
          enabled: true,
          alarms: [unresolved('var.alarm_name')],
        },
      ],
    });

    expect(result).toBeNull();
  });

  it('passes when the single listed alarm name is a partially interpolated string', () => {
    const result = scan({
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [
        {
          enabled: true,
          alarms: ['${var.env}-deploy-alarm'],
        },
      ],
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: identical enabled configuration with one entry, but the alarm
  // name is present-and-blank, identifying no alarm, so the group must be flagged.
  it('flags a deployment group whose single listed alarm name is blank', () => {
    const result = scan({
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: [
        {
          enabled: true,
          alarms: ['   '],
        },
      ],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('aws_codedeploy_deployment_group.group');
    expect(result?.resourceType).toBe('aws_codedeploy_deployment_group');
  });
});
