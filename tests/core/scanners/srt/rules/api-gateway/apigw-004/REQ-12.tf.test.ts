import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (APIGW-004): A non-OPTIONS method declares an authorizer-requiring authorization
 * type, but the identity of the associated authorizer cannot be resolved at analysis time.
 * Expected behavior: pass — the association exists, so the rule cannot prove the method is
 * uncovered and must not flag.
 *
 * Cross-resource fields are set to the target's address string, as the plan reader produces.
 */

const factory = new Apigw004TfAdapterFactory();

function run(resource: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  return apigw004Control.run(factory.bind(context) as never, context);
}

describe('APIGW-004 REQ-12 (Terraform): unresolvable authorizer association passes', () => {
  it('does not flag a POST method with CUSTOM authorization whose authorizer reference is not present in the plan', () => {
    // Reference form: authorizer lives in another state/module, so its identity is unresolvable here.
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'post_items',
      address: 'aws_api_gateway_method.post_items',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.this',
        http_method: 'POST',
        authorization: 'CUSTOM',
        authorizer_id: 'aws_api_gateway_authorizer.shared',
      },
    } as unknown as TerraformResource;

    const restApi: TerraformResource = {
      type: 'aws_api_gateway_rest_api',
      name: 'this',
      address: 'aws_api_gateway_rest_api.this',
      values: { name: 'this-api' },
    } as unknown as TerraformResource;

    expect(run(method, [method, restApi])).toBeNull();
  });

  it('does not flag an HTTP API route with JWT authorization whose referenced authorizer has an unknown api_id', () => {
    const authorizer: TerraformResource = {
      type: 'aws_apigatewayv2_authorizer',
      name: 'jwt',
      address: 'aws_apigatewayv2_authorizer.jwt',
      values: { name: 'jwt', api_id: null, authorizer_type: 'JWT' },
    } as unknown as TerraformResource;

    const route: TerraformResource = {
      type: 'aws_apigatewayv2_route',
      name: 'get_items',
      address: 'aws_apigatewayv2_route.get_items',
      values: {
        api_id: 'aws_apigatewayv2_api.this',
        route_key: 'GET /items',
        authorization_type: 'JWT',
        authorizer_id: 'aws_apigatewayv2_authorizer.jwt',
      },
    } as unknown as TerraformResource;

    expect(run(route, [route, authorizer])).toBeNull();
  });

  // Opposite outcome: the referenced authorizer resolves and provably belongs to a different
  // REST API, so no valid authorizer covers this method.
  it('flags a POST method with CUSTOM authorization whose resolvable authorizer belongs to a different API', () => {
    const authorizer: TerraformResource = {
      type: 'aws_api_gateway_authorizer',
      name: 'other',
      address: 'aws_api_gateway_authorizer.other',
      values: { name: 'other', rest_api_id: 'aws_api_gateway_rest_api.other', type: 'TOKEN' },
    } as unknown as TerraformResource;

    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'post_items',
      address: 'aws_api_gateway_method.post_items',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.this',
        http_method: 'POST',
        authorization: 'CUSTOM',
        authorizer_id: 'aws_api_gateway_authorizer.other',
      },
    } as unknown as TerraformResource;

    const result = run(method, [method, authorizer]);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_api_gateway_method.post_items');
  });
});
