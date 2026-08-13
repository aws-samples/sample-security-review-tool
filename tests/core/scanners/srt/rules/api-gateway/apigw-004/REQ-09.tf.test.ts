import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004TfAdapterFactory();

function run(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

const restApiA: TerraformResource = {
  type: 'aws_api_gateway_rest_api',
  name: 'a',
  address: 'aws_api_gateway_rest_api.a',
  values: { name: 'api-a' },
} as TerraformResource;

const restApiB: TerraformResource = {
  type: 'aws_api_gateway_rest_api',
  name: 'b',
  address: 'aws_api_gateway_rest_api.b',
  values: { name: 'api-b' },
} as TerraformResource;

/**
 * REQ-09 (APIGW-004): a non-OPTIONS method whose authorizer belongs to a DIFFERENT API
 * is not actually authorized, so the control must flag it.
 */
describe('APIGW-004 REQ-09 (Terraform): authorizer scoped to another API', () => {
  it('flags a method whose CUSTOM authorizer belongs to a different rest api (reference form)', () => {
    const authorizerForB: TerraformResource = {
      type: 'aws_api_gateway_authorizer',
      name: 'other',
      address: 'aws_api_gateway_authorizer.other',
      values: { name: 'lambda-auth', type: 'TOKEN', rest_api_id: 'aws_api_gateway_rest_api.b' },
    } as TerraformResource;

    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        http_method: 'GET',
        rest_api_id: 'aws_api_gateway_rest_api.a',
        resource_id: 'aws_api_gateway_resource.items',
        authorization: 'CUSTOM',
        authorizer_id: 'aws_api_gateway_authorizer.other',
      },
    } as TerraformResource;

    const result = run(method, [restApiA, restApiB, authorizerForB, method]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_api_gateway_method.get_items');
  });

  it('flags an apigatewayv2 route whose JWT authorizer belongs to a different api (reference form)', () => {
    const httpApiA: TerraformResource = {
      type: 'aws_apigatewayv2_api',
      name: 'a',
      address: 'aws_apigatewayv2_api.a',
      values: { name: 'http-a', protocol_type: 'HTTP' },
    } as TerraformResource;

    const httpApiB: TerraformResource = {
      type: 'aws_apigatewayv2_api',
      name: 'b',
      address: 'aws_apigatewayv2_api.b',
      values: { name: 'http-b', protocol_type: 'HTTP' },
    } as TerraformResource;

    const authorizerForB: TerraformResource = {
      type: 'aws_apigatewayv2_authorizer',
      name: 'other',
      address: 'aws_apigatewayv2_authorizer.other',
      values: { name: 'jwt-auth', authorizer_type: 'JWT', api_id: 'aws_apigatewayv2_api.b' },
    } as TerraformResource;

    const route: TerraformResource = {
      type: 'aws_apigatewayv2_route',
      name: 'get_items',
      address: 'aws_apigatewayv2_route.get_items',
      values: {
        api_id: 'aws_apigatewayv2_api.a',
        route_key: 'GET /items',
        authorization_type: 'JWT',
        authorizer_id: 'aws_apigatewayv2_authorizer.other',
      },
    } as TerraformResource;

    const result = run(route, [httpApiA, httpApiB, authorizerForB, route]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_apigatewayv2_route.get_items');
  });

  // Opposite outcome: identical fixture except the authorizer is scoped to the SAME api,
  // which satisfies the authorization requirement owned by APIGW-004.
  it('does not flag a method whose CUSTOM authorizer belongs to the same rest api', () => {
    const authorizerForA: TerraformResource = {
      type: 'aws_api_gateway_authorizer',
      name: 'own',
      address: 'aws_api_gateway_authorizer.own',
      values: { name: 'lambda-auth', type: 'TOKEN', rest_api_id: 'aws_api_gateway_rest_api.a' },
    } as TerraformResource;

    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        http_method: 'GET',
        rest_api_id: 'aws_api_gateway_rest_api.a',
        resource_id: 'aws_api_gateway_resource.items',
        authorization: 'CUSTOM',
        authorizer_id: 'aws_api_gateway_authorizer.own',
      },
    } as TerraformResource;

    expect(run(method, [restApiA, restApiB, authorizerForA, method])).toBeNull();
  });
});
