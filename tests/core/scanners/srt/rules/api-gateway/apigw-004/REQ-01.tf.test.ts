import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

// REQ-01 (primary): a non-OPTIONS API Gateway method/route with no authorization
// configuration of any kind must be flagged (publicly invokable).

const factory = new Apigw004TfAdapterFactory();

function scan(resource: TerraformResource, allResources: TerraformResource[] = [resource]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  return apigw004Control.run(factory.bind(context), context);
}

describe('APIGW-004 REQ-01 (Terraform)', () => {
  it('flags an aws_api_gateway_method with no authorization configuration', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'GET',
      },
    } as unknown as TerraformResource;

    const result = scan(method);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_api_gateway_method.get_items');
    expect(result?.resourceType).toBe('aws_api_gateway_method');
  });

  it('flags an aws_apigatewayv2_route with no authorization configuration', () => {
    const route: TerraformResource = {
      type: 'aws_apigatewayv2_route',
      name: 'post_orders',
      address: 'aws_apigatewayv2_route.post_orders',
      values: {
        api_id: 'aws_apigatewayv2_api.http_api',
        route_key: 'POST /orders',
        target: 'integrations/abc123',
      },
    } as unknown as TerraformResource;

    const result = scan(route);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_apigatewayv2_route.post_orders');
    expect(result?.resourceType).toBe('aws_apigatewayv2_route');
  });

  // Opposite outcome — nearest input that flips the verdict: the same method with
  // an accepted authorization value present. Owned by the "authorization type
  // configured" behavior of APIGW-004, included here to prove discrimination.
  it('does not flag an aws_api_gateway_method whose authorization is AWS_IAM', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'GET',
        authorization: 'AWS_IAM',
      },
    } as unknown as TerraformResource;

    expect(scan(method)).toBeNull();
  });

  it('does not flag an aws_apigatewayv2_route whose authorization_type is AWS_IAM', () => {
    const route: TerraformResource = {
      type: 'aws_apigatewayv2_route',
      name: 'post_orders',
      address: 'aws_apigatewayv2_route.post_orders',
      values: {
        api_id: 'aws_apigatewayv2_api.http_api',
        route_key: 'POST /orders',
        target: 'integrations/abc123',
        authorization_type: 'AWS_IAM',
      },
    } as unknown as TerraformResource;

    expect(scan(route)).toBeNull();
  });
});
