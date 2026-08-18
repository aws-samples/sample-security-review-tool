import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codedeploy001TfAdapterFactory();

function runControl(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  return codedeploy001Control.run(factory.bind(context), context);
}

// REQ-01 (primary): a deployment group with no alarm configuration of any kind must be flagged.
describe('CODEDEPLOY-001 Terraform: deployment group without alarm monitoring', () => {
  it('flags a deployment group defined with application, service role and deployment style but no alarm_configuration block', () => {
    const resource: TerraformResource = {
      type: 'aws_codedeploy_deployment_group',
      name: 'unmonitored',
      address: 'aws_codedeploy_deployment_group.unmonitored',
      values: {
        app_name: 'aws_codedeploy_app.app',
        deployment_group_name: 'my-deployment-group',
        service_role_arn: 'aws_iam_role.codedeploy.arn',
        deployment_style: [
          {
            deployment_type: 'BLUE_GREEN',
            deployment_option: 'WITH_TRAFFIC_CONTROL',
          },
        ],
      },
    };

    const result = runControl(resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('aws_codedeploy_deployment_group.unmonitored');
    expect(result?.resourceType).toBe('aws_codedeploy_deployment_group');
  });

  // Opposite outcome: identical group, but with one CloudWatch alarm configured — must NOT be flagged.
  it('does not flag an otherwise identical deployment group whose alarm_configuration lists one alarm', () => {
    const resource: TerraformResource = {
      type: 'aws_codedeploy_deployment_group',
      name: 'monitored',
      address: 'aws_codedeploy_deployment_group.monitored',
      values: {
        app_name: 'aws_codedeploy_app.app',
        deployment_group_name: 'my-deployment-group',
        service_role_arn: 'aws_iam_role.codedeploy.arn',
        deployment_style: [
          {
            deployment_type: 'BLUE_GREEN',
            deployment_option: 'WITH_TRAFFIC_CONTROL',
          },
        ],
        alarm_configuration: [
          {
            enabled: true,
            alarms: ['deployment-error-rate-alarm'],
          },
        ],
      },
    };

    const result = runControl(resource);

    expect(result).toBeNull();
  });
});
