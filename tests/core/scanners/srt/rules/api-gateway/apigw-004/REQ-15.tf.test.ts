import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004TfAdapterFactory();

function run(resource: TerraformResource, allResources: TerraformResource[] = [resource]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

const restApi: TerraformResource = {
  type: 'aws_api_gateway_rest_api',
  name: 'api',
  address: 'aws_api_gateway_rest_api.api',
  values: { name: 'items-api' },
} as unknown as TerraformResource;

const httpApi: TerraformResource = {
  type: 'aws_apigatewayv2_api',
  name: 'api',
  address: 'aws_apigatewayv2_api.api',
  values: { name: 'items-http-api' },
} as unknown as TerraformResource;

describe('APIGW-004 (Terraform): API keys are not authorization', () => {
  // REQ-15 owns this behavior: a non-OPTIONS method with no authorization must be flagged
  // even when api_key_required is true, since API keys only serve usage plans/metering.
  it('flags a non-OPTIONS method with authorization NONE that requires an API key', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        // reference form: rest_api_id = aws_api_gateway_rest_api.api.id
        rest_api_id: 'aws_api_gateway_rest_api.api',
        http_method: 'GET',
        authorization: 'NONE',
        api_key_required: true,
      },
    } as unknown as TerraformResource;

    const result = run(method, [restApi, method]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_api_gateway_method.get_items');
  });

  it('flags a non-OPTIONS HTTP API route with authorization_type NONE that requires an API key', () => {
    const route: TerraformResource = {
      type: 'aws_apigatewayv2_route',
      name: 'get_items',
      address: 'aws_apigatewayv2_route.get_items',
      values: {
        api_id: 'aws_apigatewayv2_api.api',
        route_key: 'GET /items',
        authorization_type: 'NONE',
        api_key_required: true,
      },
    } as unknown as TerraformResource;

    const result = run(route, [httpApi, route]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
  });

  // Opposite outcome: identical fixture except the authorization meets the standard.
  it('does not flag the same API-key-required method when AWS_IAM authorization is configured', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        http_method: 'GET',
        authorization: 'AWS_IAM',
        api_key_required: true,
      },
    } as unknown as TerraformResource;

    const result = run(method, [restApi, method]);

    expect(result).toBeNull();
  });
});
