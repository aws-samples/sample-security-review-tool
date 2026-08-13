import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004TfAdapterFactory();

function scan(resource: TerraformResource, allResources: TerraformResource[] = [resource]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 (Terraform) — REQ-04: a non-OPTIONS method using IAM-based authorization passes', () => {
  it('does not flag a REST API method whose authorization is AWS_IAM', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_item',
      address: 'aws_api_gateway_method.get_item',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'GET',
        authorization: 'AWS_IAM',
      },
    } as unknown as TerraformResource;

    expect(scan(method)).toBeNull();
  });

  it('does not flag an HTTP API route whose authorization_type is AWS_IAM', () => {
    const route: TerraformResource = {
      type: 'aws_apigatewayv2_route',
      name: 'get_item',
      address: 'aws_apigatewayv2_route.get_item',
      values: {
        api_id: 'aws_apigatewayv2_api.http_api',
        route_key: 'GET /items',
        authorization_type: 'AWS_IAM',
      },
    } as unknown as TerraformResource;

    expect(scan(route)).toBeNull();
  });

  // Opposite outcome: same non-OPTIONS method, authorization present but set to NONE.
  // Proves AWS_IAM specifically is what satisfies the rule. The unauthenticated case itself
  // is owned by the missing-authorization requirement.
  it('flags the same non-OPTIONS method when authorization is NONE', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_item',
      address: 'aws_api_gateway_method.get_item',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'GET',
        authorization: 'NONE',
      },
    } as unknown as TerraformResource;

    const result = scan(method);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('aws_api_gateway_method.get_item');
  });
});
