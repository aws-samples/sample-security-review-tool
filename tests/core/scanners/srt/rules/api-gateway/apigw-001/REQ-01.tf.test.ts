import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('APIGW-001 / Terraform / REQ-01: stage with no access logging configuration', () => {
  it('flags an aws_api_gateway_stage that has no access_log_settings block', () => {
    const stage: TerraformResource = {
      type: 'aws_api_gateway_stage',
      name: 'my_stage',
      address: 'aws_api_gateway_stage.my_stage',
      values: {
        stage_name: 'prod',
        rest_api_id: 'aws_api_gateway_rest_api.my_api',
        deployment_id: 'aws_api_gateway_deployment.my_deployment',
      },
    } as TerraformResource;

    const factory = new Apigw001TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources: [stage],
    };

    expect(factory.appliesTo(stage.type)).toBe(true);

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('APIGW-001');
    expect(result!.resourceType).toBe('aws_api_gateway_stage');
    expect(result!.resourceName).toBe('aws_api_gateway_stage.my_stage');
    expect(result!.status).toBe('Open');
  });

  it('flags an aws_apigatewayv2_stage that has no access_log_settings block', () => {
    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'my_v2_stage',
      address: 'aws_apigatewayv2_stage.my_v2_stage',
      values: {
        name: 'prod',
        api_id: 'aws_apigatewayv2_api.my_api',
      },
    } as TerraformResource;

    const factory = new Apigw001TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources: [stage],
    };

    expect(factory.appliesTo(stage.type)).toBe(true);

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('APIGW-001');
    expect(result!.resourceType).toBe('aws_apigatewayv2_stage');
    expect(result!.resourceName).toBe('aws_apigatewayv2_stage.my_v2_stage');
    expect(result!.status).toBe('Open');
  });
});
