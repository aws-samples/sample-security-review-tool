import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(resource: TerraformResource, allResources: TerraformResource[]): TfContext {
  return {
    projectName: 'test-project',
    resource,
    allResources,
  };
}

describe('APIGW-001 REQ-02 (TF): access logging configured with in-template log group destination and non-zero retention', () => {
  it('passes for aws_api_gateway_stage with access_log_settings referencing an in-plan log group (reference form)', () => {
    const logGroup: TerraformResource = {
      type: 'aws_cloudwatch_log_group',
      name: 'access',
      address: 'aws_cloudwatch_log_group.access',
      values: {
        name: '/aws/apigateway/access',
        retention_in_days: 30,
      },
    } as unknown as TerraformResource;

    const stage: TerraformResource = {
      type: 'aws_api_gateway_stage',
      name: 'prod',
      address: 'aws_api_gateway_stage.prod',
      values: {
        stage_name: 'prod',
        access_log_settings: [
          {
            destination_arn: 'aws_cloudwatch_log_group.access',
            format: '$context.requestId',
          },
        ],
      },
    } as unknown as TerraformResource;

    const factory = new Apigw001TfAdapterFactory();
    expect(factory.appliesTo('aws_api_gateway_stage')).toBe(true);
    const ctx = buildContext(stage, [stage, logGroup]);
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);
    expect(result).toBeNull();
  });

  it('passes for aws_apigatewayv2_stage with access_log_settings referencing an in-plan log group (reference form)', () => {
    const logGroup: TerraformResource = {
      type: 'aws_cloudwatch_log_group',
      name: 'http_access',
      address: 'aws_cloudwatch_log_group.http_access',
      values: {
        name: '/aws/apigateway/http-access',
        retention_in_days: 90,
      },
    } as unknown as TerraformResource;

    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'default',
      address: 'aws_apigatewayv2_stage.default',
      values: {
        name: '$default',
        access_log_settings: [
          {
            destination_arn: 'aws_cloudwatch_log_group.http_access',
            format: '$context.requestId',
          },
        ],
      },
    } as unknown as TerraformResource;

    const factory = new Apigw001TfAdapterFactory();
    expect(factory.appliesTo('aws_apigatewayv2_stage')).toBe(true);
    const ctx = buildContext(stage, [stage, logGroup]);
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);
    expect(result).toBeNull();
  });

  it('passes for aws_api_gateway_stage with access_log_settings referencing an in-plan log group (literal form)', () => {
    const logGroup: TerraformResource = {
      type: 'aws_cloudwatch_log_group',
      name: 'access',
      address: 'aws_cloudwatch_log_group.access',
      values: {
        name: '/aws/apigateway/access',
        retention_in_days: 14,
      },
    } as unknown as TerraformResource;

    const stage: TerraformResource = {
      type: 'aws_api_gateway_stage',
      name: 'prod',
      address: 'aws_api_gateway_stage.prod',
      values: {
        stage_name: 'prod',
        access_log_settings: [
          {
            destination_arn: 'arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/access',
            format: '$context.requestId',
          },
        ],
      },
    } as unknown as TerraformResource;

    const factory = new Apigw001TfAdapterFactory();
    const ctx = buildContext(stage, [stage, logGroup]);
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);
    expect(result).toBeNull();
  });
});
