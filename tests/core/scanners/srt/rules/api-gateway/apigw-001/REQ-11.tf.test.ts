import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('APIGW-001 Terraform - REQ-11: log group retention is unresolvable', () => {
  it('passes when aws_api_gateway_stage references an in-plan log group whose retention_in_days is unknown at plan time (null)', () => {
    const logGroup: TerraformResource = {
      type: 'aws_cloudwatch_log_group',
      name: 'access',
      address: 'aws_cloudwatch_log_group.access',
      values: {
        name: '/aws/apigateway/access-logs',
        // null = unknown at plan time
        retention_in_days: null,
      },
    };

    const stage: TerraformResource = {
      type: 'aws_api_gateway_stage',
      name: 'prod',
      address: 'aws_api_gateway_stage.prod',
      values: {
        stage_name: 'prod',
        access_log_settings: [
          {
            // Reference form: aws_cloudwatch_log_group.access.arn collapses to address.
            destination_arn: 'aws_cloudwatch_log_group.access',
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

  it('passes when aws_apigatewayv2_stage references an in-plan log group by literal name and retention_in_days is unknown (null)', () => {
    const logGroup: TerraformResource = {
      type: 'aws_cloudwatch_log_group',
      name: 'access_v2',
      address: 'aws_cloudwatch_log_group.access_v2',
      values: {
        name: '/aws/apigateway/v2-access-logs',
        retention_in_days: null,
      },
    };

    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'default',
      address: 'aws_apigatewayv2_stage.default',
      values: {
        name: '$default',
        access_log_settings: [
          {
            // Literal form: user wrote the log group ARN as a string containing the name.
            destination_arn: 'arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/v2-access-logs',
            format: '$context.requestId',
          },
        ],
      },
    };

    const factory = new Apigw001TfAdapterFactory();
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
