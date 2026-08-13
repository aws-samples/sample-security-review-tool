import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004TfAdapterFactory();

const jwtAuthorizer: TerraformResource = {
  type: 'aws_apigatewayv2_authorizer',
  name: 'jwt',
  address: 'aws_apigatewayv2_authorizer.jwt',
  values: {
    name: 'jwt-authorizer',
    api_id: 'aws_apigatewayv2_api.http_api',
    authorizer_type: 'JWT',
    identity_sources: ['$request.header.Authorization'],
  },
} as unknown as TerraformResource;

function route(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_apigatewayv2_route',
    name: 'get_items',
    address: 'aws_apigatewayv2_route.get_items',
    values,
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 (Terraform) - JWT authorization on a non-OPTIONS route', () => {
  // Primary behavior owned by this requirement.
  it('passes a non-OPTIONS route using JWT authorization with an authorizer referenced by address', () => {
    const resource = route({
      api_id: 'aws_apigatewayv2_api.http_api',
      route_key: 'GET /items',
      authorization_type: 'JWT',
      // authorizer_id = aws_apigatewayv2_authorizer.jwt.id
      authorizer_id: 'aws_apigatewayv2_authorizer.jwt',
      target: 'integrations/abc123',
    });

    expect(run(resource, [resource, jwtAuthorizer])).toBeNull();
  });

  it('passes a non-OPTIONS route using JWT authorization with the authorizer wired by literal name', () => {
    const resource = route({
      api_id: 'aws_apigatewayv2_api.http_api',
      route_key: 'GET /items',
      authorization_type: 'JWT',
      authorizer_id: 'jwt-authorizer',
      target: 'integrations/abc123',
    });

    expect(run(resource, [resource, jwtAuthorizer])).toBeNull();
  });

  // Opposite outcome: same JWT authorization type, but no authorizer attached.
  it('flags a non-OPTIONS route declaring JWT authorization with no associated authorizer', () => {
    const resource = route({
      api_id: 'aws_apigatewayv2_api.http_api',
      route_key: 'GET /items',
      authorization_type: 'JWT',
      target: 'integrations/abc123',
    });

    const result = run(resource, [resource, jwtAuthorizer]);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_apigatewayv2_route.get_items');
  });
});
