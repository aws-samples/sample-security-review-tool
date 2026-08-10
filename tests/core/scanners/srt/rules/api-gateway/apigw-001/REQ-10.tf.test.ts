import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('APIGW-001 TF — REQ-10: V2 stage with access logging to in-plan log group with explicit non-zero retention', () => {
  it('passes when aws_apigatewayv2_stage references an in-plan aws_cloudwatch_log_group with explicit retention_in_days > 0', () => {
    const logGroup: TerraformResource = {
      type: 'aws_cloudwatch_log_group',
      name: 'access_logs',
      address: 'aws_cloudwatch_log_group.access_logs',
      values: {
        name: '/aws/apigateway/my-api-access',
        retention_in_days: 30,
      },
    };

    // Reference form — destination_arn collapsed to the log group's address.
    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'prod',
      address: 'aws_apigatewayv2_stage.prod',
      values: {
        name: 'prod',
        access_log_settings: [
          {
            destination_arn: 'aws_cloudwatch_log_group.access_logs',
            format: '$context.requestId',
          },
        ],
      },
    };

    const factory = new Apigw001TfAdapterFactory();
    expect(factory.appliesTo(stage.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources: [stage, logGroup],
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
