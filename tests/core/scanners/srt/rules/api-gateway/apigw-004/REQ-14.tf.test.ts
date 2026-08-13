import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004TfAdapterFactory();

const jwtAuthorizer: TerraformResource = {
  type: 'aws_apigatewayv2_authorizer',
  name: 'jwt',
  address: 'aws_apigatewayv2_authorizer.jwt',
  values: { name: 'jwt', api_id: 'aws_apigatewayv2_api.http', authorizer_type: 'JWT' },
} as unknown as TerraformResource;

function run(resource: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources: [...allResources, resource] };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 (Terraform) - catch-all route with valid authorization', () => {
  // Primary behavior owned by REQ-14: a broadly matching route still passes when it carries
  // a valid authorization type and an authorizer where the type requires one.
  it('passes a $default route (any path, any method) using JWT with a referenced authorizer', () => {
    const route: TerraformResource = {
      type: 'aws_apigatewayv2_route',
      name: 'catch_all',
      address: 'aws_apigatewayv2_route.catch_all',
      values: {
        api_id: 'aws_apigatewayv2_api.http',
        route_key: '$default',
        authorization_type: 'JWT',
        // reference form: user wrote aws_apigatewayv2_authorizer.jwt.id in HCL
        authorizer_id: 'aws_apigatewayv2_authorizer.jwt',
      },
    } as unknown as TerraformResource;

    expect(run(route, [jwtAuthorizer])).toBeNull();
  });

  it('passes an ANY method on a {proxy+} resource using AWS_IAM', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'catch_all',
      address: 'aws_api_gateway_method.catch_all',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.rest',
        resource_id: 'aws_api_gateway_resource.proxy',
        http_method: 'ANY',
        authorization: 'AWS_IAM',
      },
    } as unknown as TerraformResource;

    expect(run(method, [])).toBeNull();
  });

  // Opposite outcome: identical catch-all route, but with an authorization type that is not valid.
  it('flags the same catch-all route when its authorization type is NONE', () => {
    const route: TerraformResource = {
      type: 'aws_apigatewayv2_route',
      name: 'catch_all',
      address: 'aws_apigatewayv2_route.catch_all',
      values: {
        api_id: 'aws_apigatewayv2_api.http',
        route_key: '$default',
        authorization_type: 'NONE',
      },
    } as unknown as TerraformResource;

    const result = run(route, [jwtAuthorizer]);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_apigatewayv2_route.catch_all');
  });
});
