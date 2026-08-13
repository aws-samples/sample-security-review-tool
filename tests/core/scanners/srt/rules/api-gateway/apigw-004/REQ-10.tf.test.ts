import { describe, it, expect } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (APIGW-004): An authorization value that is present but EMPTY is not one of the
 * accepted values (AWS_IAM, COGNITO_USER_POOLS, CUSTOM) and therefore must be flagged.
 */

const factory = new Apigw004TfAdapterFactory();

function scan(target: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = { projectName: 'test-project', resource: target, allResources };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

const restApi: TerraformResource = {
  type: 'aws_api_gateway_rest_api',
  name: 'api',
  address: 'aws_api_gateway_rest_api.api',
  values: { name: 'my-api' },
} as unknown as TerraformResource;

// Reference form: rest_api_id was written as aws_api_gateway_rest_api.api.id in HCL.
function restMethod(authorization: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method',
    name: 'get_items',
    address: 'aws_api_gateway_method.get_items',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      resource_id: 'aws_api_gateway_resource.items',
      http_method: 'GET',
      authorization,
    },
  } as unknown as TerraformResource;
}

const httpApi: TerraformResource = {
  type: 'aws_apigatewayv2_api',
  name: 'http',
  address: 'aws_apigatewayv2_api.http',
  values: { name: 'my-http-api' },
} as unknown as TerraformResource;

// Reference form: api_id was written as aws_apigatewayv2_api.http.id in HCL.
function httpRoute(authorizationType: string): TerraformResource {
  return {
    type: 'aws_apigatewayv2_route',
    name: 'get_items',
    address: 'aws_apigatewayv2_route.get_items',
    values: {
      api_id: 'aws_apigatewayv2_api.http',
      route_key: 'GET /items',
      authorization_type: authorizationType,
    },
  } as unknown as TerraformResource;
}

describe('APIGW-004 REQ-10 (Terraform): empty authorization type', () => {
  it('flags an aws_api_gateway_method whose authorization is an empty string', () => {
    const method = restMethod('');
    const result = scan(method, [restApi, method]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_api_gateway_method.get_items');
  });

  it('flags an aws_apigatewayv2_route whose authorization_type is an empty string', () => {
    const route = httpRoute('');
    const result = scan(route, [httpApi, route]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_apigatewayv2_route.get_items');
  });

  // Opposite outcome: identical fixture except the authorization is a real accepted value.
  it('does not flag the same method when authorization is the accepted value AWS_IAM', () => {
    const method = restMethod('AWS_IAM');
    expect(scan(method, [restApi, method])).toBeNull();
  });

  // Opposite outcome for the V2 route family.
  it('does not flag the same route when authorization_type is the accepted value AWS_IAM', () => {
    const route = httpRoute('AWS_IAM');
    expect(scan(route, [httpApi, route])).toBeNull();
  });
});
