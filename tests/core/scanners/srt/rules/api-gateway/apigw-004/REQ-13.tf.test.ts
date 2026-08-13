import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (APIGW-004): Rules evaluate one resource at a time. When a plan contains several
 * non-OPTIONS methods and some siblings are unauthenticated, the assessed method must pass
 * as long as it declares a valid authorization type with any required authorizer.
 */

const factory = new Apigw004TfAdapterFactory();

function assess(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

const restAuthorizer: TerraformResource = {
  type: 'aws_api_gateway_authorizer',
  name: 'pool',
  address: 'aws_api_gateway_authorizer.pool',
  values: { name: 'pool-authorizer', type: 'COGNITO_USER_POOLS', rest_api_id: 'aws_api_gateway_rest_api.items' },
} as unknown as TerraformResource;

// Reference form: HCL wrote authorizer_id = aws_api_gateway_authorizer.pool.id
function assessedRestMethod(authorization: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method',
    name: 'get_items',
    address: 'aws_api_gateway_method.get_items',
    values: {
      http_method: 'GET',
      rest_api_id: 'aws_api_gateway_rest_api.items',
      authorization,
      authorizer_id: 'aws_api_gateway_authorizer.pool',
    },
  } as unknown as TerraformResource;
}

const unauthenticatedSiblings: TerraformResource[] = [
  {
    type: 'aws_api_gateway_method',
    name: 'post_items',
    address: 'aws_api_gateway_method.post_items',
    values: { http_method: 'POST', rest_api_id: 'aws_api_gateway_rest_api.items', authorization: 'NONE' },
  },
  {
    type: 'aws_api_gateway_method',
    name: 'put_items',
    address: 'aws_api_gateway_method.put_items',
    values: { http_method: 'PUT', rest_api_id: 'aws_api_gateway_rest_api.items', authorization: 'NONE' },
  },
] as unknown as TerraformResource[];

function assessedRoute(authorizationType: string): TerraformResource {
  return {
    type: 'aws_apigatewayv2_route',
    name: 'get_items',
    address: 'aws_apigatewayv2_route.get_items',
    values: {
      api_id: 'aws_apigatewayv2_api.items',
      route_key: 'GET /items',
      authorization_type: authorizationType,
    },
  } as unknown as TerraformResource;
}

const unauthenticatedRouteSiblings: TerraformResource[] = [
  {
    type: 'aws_apigatewayv2_route',
    name: 'post_items',
    address: 'aws_apigatewayv2_route.post_items',
    values: { api_id: 'aws_apigatewayv2_api.items', route_key: 'POST /items', authorization_type: 'NONE' },
  },
  {
    type: 'aws_apigatewayv2_route',
    name: 'delete_items',
    address: 'aws_apigatewayv2_route.delete_items',
    values: { api_id: 'aws_apigatewayv2_api.items', route_key: 'DELETE /items/{id}', authorization_type: 'NONE' },
  },
] as unknown as TerraformResource[];

describe('APIGW-004 REQ-13 (Terraform): assessed method is authorized while siblings are not', () => {
  it('passes the assessed REST method with COGNITO_USER_POOLS and a referenced authorizer, despite unauthenticated siblings', () => {
    const method = assessedRestMethod('COGNITO_USER_POOLS');
    expect(assess(method, [method, restAuthorizer, ...unauthenticatedSiblings])).toBeNull();
  });

  it('passes the assessed HTTP API route with AWS_IAM, despite unauthenticated sibling routes', () => {
    const route = assessedRoute('AWS_IAM');
    expect(assess(route, [route, ...unauthenticatedRouteSiblings])).toBeNull();
  });

  // Opposite outcome: only the assessed resource's own authorization value changes to an
  // unauthorized one. The "missing authorization" behavior itself is owned by that
  // requirement; asserted here so this file discriminates.
  it('flags the assessed REST method when its own authorization is NONE (siblings unchanged)', () => {
    const method = assessedRestMethod('NONE');
    const result = assess(method, [method, restAuthorizer, ...unauthenticatedSiblings]);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_api_gateway_method.get_items');
  });

  it('flags the assessed HTTP API route when its own authorization type is NONE (siblings unchanged)', () => {
    const route = assessedRoute('NONE');
    const result = assess(route, [route, ...unauthenticatedRouteSiblings]);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_apigatewayv2_route.get_items');
  });
});
