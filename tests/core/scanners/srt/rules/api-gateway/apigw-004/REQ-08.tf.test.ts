import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004TfAdapterFactory();

function scan(resource: TerraformResource, allResources: TerraformResource[] = []): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource, ...allResources],
  };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 (Terraform) — user-pool-based authorization without an associated authorizer', () => {
  // Primary behavior owned by REQ-08: COGNITO_USER_POOLS / JWT authorization must be
  // backed by an associated authorizer, otherwise no token validation occurs.
  it('flags a non-OPTIONS REST method with COGNITO_USER_POOLS authorization and no authorizer_id', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'GET',
        authorization: 'COGNITO_USER_POOLS',
      },
    } as unknown as TerraformResource;

    const result = scan(method);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_api_gateway_method.get_items');
    expect(result?.resourceType).toBe('aws_api_gateway_method');
  });

  it('flags a non-OPTIONS HTTP API route with JWT (user pool) authorization and no authorizer_id', () => {
    const route: TerraformResource = {
      type: 'aws_apigatewayv2_route',
      name: 'get_items',
      address: 'aws_apigatewayv2_route.get_items',
      values: {
        api_id: 'aws_apigatewayv2_api.http_api',
        route_key: 'GET /items',
        authorization_type: 'JWT',
      },
    } as unknown as TerraformResource;

    const result = scan(route);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_apigatewayv2_route.get_items');
  });

  // Opposite outcome: identical method, but the user-pool authorization IS backed by an
  // associated authorizer. Reference form — HCL wrote aws_api_gateway_authorizer.pool.id,
  // which the plan reader collapses to the authorizer's address string.
  it('does not flag the same method when an authorizer is associated with it', () => {
    const authorizer: TerraformResource = {
      type: 'aws_api_gateway_authorizer',
      name: 'pool',
      address: 'aws_api_gateway_authorizer.pool',
      values: { name: 'pool-authorizer', type: 'COGNITO_USER_POOLS' },
    } as unknown as TerraformResource;

    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'GET',
        authorization: 'COGNITO_USER_POOLS',
        authorizer_id: 'aws_api_gateway_authorizer.pool',
      },
    } as unknown as TerraformResource;

    const result = scan(method, [authorizer]);

    expect(result).toBeNull();
  });
});
