import { describe, it, expect } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codedeploy001TfAdapterFactory();

const alarmResource: TerraformResource = {
  type: 'aws_cloudwatch_metric_alarm',
  name: 'deploy',
  address: 'aws_cloudwatch_metric_alarm.deploy',
  values: {
    alarm_name: 'deploy-errors',
    comparison_operator: 'GreaterThanThreshold',
    evaluation_periods: 1,
    metric_name: 'Errors',
    namespace: 'AWS/Lambda',
    threshold: 1,
  },
} as unknown as TerraformResource;

function buildDeploymentGroup(alarmConfiguration: unknown): TerraformResource {
  return {
    type: 'aws_codedeploy_deployment_group',
    name: 'app',
    address: 'aws_codedeploy_deployment_group.app',
    values: {
      app_name: 'my-app',
      deployment_group_name: 'my-group',
      service_role_arn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
      alarm_configuration: alarmConfiguration,
    },
  } as unknown as TerraformResource;
}

function runControl(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource, alarmResource],
  };
  const adapter = factory.bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 (Terraform) - enabled alarm_configuration naming a declared alarm', () => {
  // Primary behavior owned by this requirement: an enabled alarm_configuration block whose
  // alarms list names a CloudWatch alarm declared in the same project must pass.
  it('does not report a finding when the enabled alarm_configuration names a declared CloudWatch alarm', () => {
    const resource = buildDeploymentGroup([
      { enabled: true, alarms: ['deploy-errors'] },
    ]);

    expect(runControl(resource)).toBeNull();
  });

  it('applies to aws_codedeploy_deployment_group resources', () => {
    expect(factory.appliesTo('aws_codedeploy_deployment_group')).toBe(true);
  });

  // Opposite outcome: identical resource except the enabled alarm_configuration
  // names no alarm at all, so nothing monitors the deployment.
  it('reports a finding when the enabled alarm_configuration lists no alarms', () => {
    const resource = buildDeploymentGroup([
      { enabled: true, alarms: [] },
    ]);

    const result = runControl(resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('aws_codedeploy_deployment_group.app');
  });
});
