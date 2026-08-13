import { describe, it, expect } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004TfAdapterFactory();

function scan(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  return apigw004Control.run(factory.bind(context), context);
}

describe('APIGW-004 REQ-03 (Terraform): OPTIONS methods are excluded from the authorization requirement', () => {
  it('passes an OPTIONS method with no authorization configured at all', () => {
    const result = scan({
      type: 'aws_api_gateway_method',
      name: 'options',
      address: 'aws_api_gateway_method.options',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'OPTIONS',
      },
    } as unknown as TerraformResource);

    expect(result).toBeNull();
  });

  it('passes an OPTIONS method that explicitly declares authorization NONE', () => {
    const result = scan({
      type: 'aws_api_gateway_method',
      name: 'options_none',
      address: 'aws_api_gateway_method.options_none',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'OPTIONS',
        authorization: 'NONE',
      },
    } as unknown as TerraformResource);

    expect(result).toBeNull();
  });

  it('passes an HTTP API OPTIONS route that explicitly declares authorization_type NONE', () => {
    const result = scan({
      type: 'aws_apigatewayv2_route',
      name: 'options_route',
      address: 'aws_apigatewayv2_route.options_route',
      values: {
        api_id: 'aws_apigatewayv2_api.http',
        route_key: 'OPTIONS /items',
        authorization_type: 'NONE',
      },
    } as unknown as TerraformResource);

    expect(result).toBeNull();
  });

  // Opposite outcome: the primary "missing authorization" behavior is owned by the
  // main APIGW-004 requirement. Only the verb changes here (OPTIONS -> POST), which
  // is what this scenario's exclusion turns on.
  it('flags an otherwise identical POST method with authorization NONE', () => {
    const result = scan({
      type: 'aws_api_gateway_method',
      name: 'post_none',
      address: 'aws_api_gateway_method.post_none',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'POST',
        authorization: 'NONE',
      },
    } as unknown as TerraformResource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_api_gateway_method.post_none');
  });
});
