import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const unresolved = (ref: string): string => `__unresolved__:${ref}`;

function scan(resource: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = new Codedeploy001TfAdapterFactory().bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

function deploymentGroup(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_codedeploy_deployment_group',
    name: 'app',
    address: 'aws_codedeploy_deployment_group.app',
    values: {
      app_name: 'app',
      deployment_group_name: 'app-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      ...values,
    },
  } as TerraformResource;
}

describe('CODEDEPLOY-001 (Terraform) - alarm configuration gated by an unresolvable input', () => {
  // Primary behaviour owned by this requirement: whether the alarm monitoring block
  // takes effect is driven by a variable with no reachable default, i.e. a
  // deployment-time input. One value keeps monitoring on, another turns it off, so
  // the scanner cannot assert a breach.
  it('does not flag when the alarm configuration hinges on an unresolved deployment-time input', () => {
    const result = scan(deploymentGroup({
      alarm_configuration: [
        {
          enabled: unresolved('var.monitor_deployments'),
          alarms: [unresolved('var.deployment_alarm_names')],
        },
      ],
    }));

    expect(result).toBeNull();
  });

  it('does not flag when the whole alarm_configuration argument is an unresolved reference', () => {
    const result = scan(deploymentGroup({
      alarm_configuration: unresolved('var.alarm_configuration'),
    }));

    expect(result).toBeNull();
  });

  // The source reader keeps a `dynamic "alarm_configuration"` block under `dynamic`,
  // so the configuration's presence is decided by an unresolvable for_each.
  it('does not flag when a dynamic alarm_configuration is gated by an unresolved for_each', () => {
    const result = scan(deploymentGroup({
      dynamic: {
        alarm_configuration: [
          {
            for_each: unresolved('var.alarm_enabled ? [true] : []'),
            content: [{ enabled: false, alarms: [] }],
          },
        ],
      },
    }));

    expect(result).toBeNull();
  });

  it('flags when a dynamic alarm_configuration has a for_each that yields nothing', () => {
    const result = scan(deploymentGroup({
      dynamic: {
        alarm_configuration: [
          {
            for_each: [],
            content: [{ enabled: true, alarms: ['deployment-errors'] }],
          },
        ],
      },
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
  });

  // Opposite outcome: identical deployment group, except the input is resolved to a
  // known state with monitoring on and no alarms named. The scanner can see the
  // state, so it must flag it.
  it('flags when the resolved alarm configuration enables monitoring but names no alarms', () => {
    const result = scan(deploymentGroup({
      alarm_configuration: [
        {
          enabled: true,
          alarms: [],
        },
      ],
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('aws_codedeploy_deployment_group.app');
    expect(result?.resourceType).toBe('aws_codedeploy_deployment_group');
  });
});
