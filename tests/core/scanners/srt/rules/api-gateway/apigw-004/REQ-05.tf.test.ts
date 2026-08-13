import { describe, expect, it } from 'vitest';

import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (APIGW-004): A non-OPTIONS method that uses a CUSTOM (Lambda) authorization
 * type AND references an authorizer defined for the same API is compliant.
 */

const factory = new Apigw004TfAdapterFactory();

const restApi: TerraformResource = {
  type: 'aws_api_gateway_rest_api',
  name: 'orders',
  address: 'aws_api_gateway_rest_api.orders',
  values: { name: 'orders-api' },
} as unknown as TerraformResource;

const lambdaAuthorizer: TerraformResource = {
  type: 'aws_api_gateway_authorizer',
  name: 'custom',
  address: 'aws_api_gateway_authorizer.custom',
  values: {
    name: 'orders-lambda-authorizer',
    type: 'TOKEN',
    rest_api_id: 'aws_api_gateway_rest_api.orders',
  },
} as unknown as TerraformResource;

const httpApi: TerraformResource = {
  type: 'aws_apigatewayv2_api',
  name: 'orders',
  address: 'aws_apigatewayv2_api.orders',
  values: { name: 'orders-http-api', protocol_type: 'HTTP' },
} as unknown as TerraformResource;

const httpAuthorizer: TerraformResource = {
  type: 'aws_apigatewayv2_authorizer',
  name: 'custom',
  address: 'aws_apigatewayv2_authorizer.custom',
  values: {
    name: 'http-lambda-authorizer',
    authorizer_type: 'REQUEST',
    api_id: 'aws_apigatewayv2_api.orders',
  },
} as unknown as TerraformResource;

function run(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [restApi, lambdaAuthorizer, httpApi, httpAuthorizer, resource],
  };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 REQ-05 (Terraform): CUSTOM authorization with an authorizer on the same API', () => {
  it('passes a non-OPTIONS method whose authorizer_id references an authorizer for the same API', () => {
    // Reference form — HCL wrote aws_api_gateway_authorizer.custom.id
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_orders',
      address: 'aws_api_gateway_method.get_orders',
      values: {
        http_method: 'GET',
        rest_api_id: 'aws_api_gateway_rest_api.orders',
        authorization: 'CUSTOM',
        authorizer_id: 'aws_api_gateway_authorizer.custom',
      },
    } as unknown as TerraformResource;

    expect(run(method)).toBeNull();
  });

  it('passes a non-OPTIONS method wired to the authorizer by literal id', () => {
    // Literal form — user pasted the authorizer id string in HCL
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_orders',
      address: 'aws_api_gateway_method.get_orders',
      values: {
        http_method: 'GET',
        rest_api_id: 'aws_api_gateway_rest_api.orders',
        authorization: 'CUSTOM',
        authorizer_id: 'abc123',
      },
    } as unknown as TerraformResource;

    expect(run(method)).toBeNull();
  });

  it('passes a non-OPTIONS HTTP API route with CUSTOM authorization and an authorizer for the same API', () => {
    const route: TerraformResource = {
      type: 'aws_apigatewayv2_route',
      name: 'get_orders',
      address: 'aws_apigatewayv2_route.get_orders',
      values: {
        api_id: 'aws_apigatewayv2_api.orders',
        route_key: 'GET /orders',
        authorization_type: 'CUSTOM',
        authorizer_id: 'aws_apigatewayv2_authorizer.custom',
      },
    } as unknown as TerraformResource;

    expect(run(route)).toBeNull();
  });

  // Opposite outcome: authorization type present but not an accepted mode.
  // Primary behavior for the NONE/unauthenticated case belongs to the
  // missing-authorization requirement; asserted here only to prove this file
  // discriminates on the authorization type rather than always passing.
  it('flags an otherwise identical method whose authorization is NONE', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_orders',
      address: 'aws_api_gateway_method.get_orders',
      values: {
        http_method: 'GET',
        rest_api_id: 'aws_api_gateway_rest_api.orders',
        authorization: 'NONE',
        authorizer_id: 'aws_api_gateway_authorizer.custom',
      },
    } as unknown as TerraformResource;

    const result = run(method);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
  });
});
