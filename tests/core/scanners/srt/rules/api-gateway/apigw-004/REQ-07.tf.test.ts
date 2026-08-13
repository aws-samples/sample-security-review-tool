import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004TfAdapterFactory();

const restAuthorizer: TerraformResource = {
  type: 'aws_api_gateway_authorizer',
  name: 'user_pool',
  address: 'aws_api_gateway_authorizer.user_pool',
  values: {
    name: 'user-pool-authorizer',
    type: 'COGNITO_USER_POOLS',
    rest_api_id: 'aws_api_gateway_rest_api.api',
    provider_arns: ['arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_abc123'],
  },
} as unknown as TerraformResource;

const httpAuthorizer: TerraformResource = {
  type: 'aws_apigatewayv2_authorizer',
  name: 'jwt',
  address: 'aws_apigatewayv2_authorizer.jwt',
  values: {
    name: 'jwt-authorizer',
    authorizer_type: 'JWT',
    api_id: 'aws_apigatewayv2_api.api',
  },
} as unknown as TerraformResource;

function run(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [restAuthorizer, httpAuthorizer, resource],
  };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 (Terraform) — non-OPTIONS method with user-pool authorization and an associated authorizer', () => {
  // Primary behavior owned by this requirement: COGNITO_USER_POOLS + authorizer => pass.
  it('passes a method using COGNITO_USER_POOLS with an authorizer_id referencing the API authorizer', () => {
    // Reference form: HCL had authorizer_id = aws_api_gateway_authorizer.user_pool.id
    const result = run({
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'GET',
        authorization: 'COGNITO_USER_POOLS',
        authorizer_id: restAuthorizer.address,
      },
    } as unknown as TerraformResource);

    expect(result).toBeNull();
  });

  it('passes an HTTP API route using JWT (user pool) authorization with an associated authorizer', () => {
    const result = run({
      type: 'aws_apigatewayv2_route',
      name: 'get_items',
      address: 'aws_apigatewayv2_route.get_items',
      values: {
        api_id: 'aws_apigatewayv2_api.api',
        route_key: 'GET /items',
        authorization_type: 'JWT',
        authorizer_id: httpAuthorizer.address,
      },
    } as unknown as TerraformResource);

    expect(result).toBeNull();
  });

  // Opposite outcome: authorization value present but not a user-pool/IAM/custom mode.
  it('flags the same method when authorization is NONE instead of COGNITO_USER_POOLS', () => {
    const result = run({
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'GET',
        authorization: 'NONE',
        authorizer_id: restAuthorizer.address,
      },
    } as unknown as TerraformResource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_api_gateway_method.get_items');
  });

  // Opposite outcome: user-pool mode declared but no authorizer associated with the method.
  it('flags a COGNITO_USER_POOLS method whose authorizer_id is empty', () => {
    const result = run({
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'GET',
        authorization: 'COGNITO_USER_POOLS',
        authorizer_id: '',
      },
    } as unknown as TerraformResource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
  });
});
