import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('APIGW-001 / REQ-09 (TF): aws_apigatewayv2_stage has no access log settings configured', () => {
  const factory = new Apigw001TfAdapterFactory();

  it('flags an aws_apigatewayv2_stage with no access_log_settings field', () => {
    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'http',
      address: 'aws_apigatewayv2_stage.http',
      values: {
        api_id: 'aws_apigatewayv2_api.http_api',
        name: '$default',
        auto_deploy: true,
      },
    } as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources: [stage],
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('APIGW-001');
    expect(result!.resourceType).toBe('aws_apigatewayv2_stage');
    expect(result!.resourceName).toBe('aws_apigatewayv2_stage.http');
    expect(result!.issue).toMatch(/access logging/i);
  });

  it('flags an aws_apigatewayv2_stage when access_log_settings is an empty array', () => {
    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'ws',
      address: 'aws_apigatewayv2_stage.ws',
      values: {
        api_id: 'aws_apigatewayv2_api.ws_api',
        name: 'prod',
        access_log_settings: [],
      },
    } as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources: [stage],
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('APIGW-001');
    expect(result!.issue).toMatch(/access logging/i);
  });

  it('flags an aws_apigatewayv2_stage when access_log_settings is an empty object', () => {
    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'http2',
      address: 'aws_apigatewayv2_stage.http2',
      values: {
        api_id: 'aws_apigatewayv2_api.http_api',
        name: '$default',
        access_log_settings: {},
      },
    } as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources: [stage],
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('APIGW-001');
    expect(result!.issue).toMatch(/access logging/i);
  });
});
