import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004TfAdapterFactory();

const authorizer: TerraformResource = {
  type: 'aws_api_gateway_authorizer',
  name: 'lambda_auth',
  address: 'aws_api_gateway_authorizer.lambda_auth',
  values: { name: 'lambda-auth', type: 'TOKEN' },
} as unknown as TerraformResource;

function run(resource: TerraformResource, others: TerraformResource[] = []): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource, ...others],
  };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 (Terraform) — CUSTOM authorization must be backed by an associated authorizer', () => {
  // Primary behavior owned by this requirement: CUSTOM type without an authorizer must be flagged.
  it('flags a non-OPTIONS method with authorization CUSTOM and no authorizer_id', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        http_method: 'GET',
        authorization: 'CUSTOM',
      },
    } as unknown as TerraformResource;

    const result = run(method);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_api_gateway_method.get_items');
    expect(result?.resourceType).toBe('aws_api_gateway_method');
  });

  it('flags an apigatewayv2 route with authorization_type CUSTOM and no authorizer_id', () => {
    const route: TerraformResource = {
      type: 'aws_apigatewayv2_route',
      name: 'post_items',
      address: 'aws_apigatewayv2_route.post_items',
      values: {
        route_key: 'POST /items',
        authorization_type: 'CUSTOM',
      },
    } as unknown as TerraformResource;

    const result = run(route);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_apigatewayv2_route.post_items');
  });

  // Opposite outcome: identical method, but the CUSTOM authorization is backed by an authorizer
  // (reference form — the plan reader collapses aws_api_gateway_authorizer.lambda_auth.id to the address).
  it('does not flag the same method when authorizer_id references a custom authorizer', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        http_method: 'GET',
        authorization: 'CUSTOM',
        authorizer_id: 'aws_api_gateway_authorizer.lambda_auth',
      },
    } as unknown as TerraformResource;

    const result = run(method, [authorizer]);

    expect(result).toBeNull();
  });

  it('does not flag the same method when authorizer_id is a literal authorizer id', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        http_method: 'GET',
        authorization: 'CUSTOM',
        authorizer_id: 'abc123',
      },
    } as unknown as TerraformResource;

    const result = run(method);

    expect(result).toBeNull();
  });
});
