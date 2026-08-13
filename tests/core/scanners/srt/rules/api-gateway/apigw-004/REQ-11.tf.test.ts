import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004TfAdapterFactory();

function scan(resource: TerraformResource, allResources: TerraformResource[] = [resource]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

/**
 * REQ-11 (primary behavior owned by APIGW-004): when the authorization argument of a
 * non-OPTIONS method is driven by a conditional expression the plan cannot resolve,
 * the plan reader records it as null. An indeterminate value must not be flagged.
 */
describe('APIGW-004 Terraform — indeterminate authorization type', () => {
  it('returns no finding when a non-OPTIONS REST method authorization is unresolved (null) at plan time', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        http_method: 'GET',
        // authorization = var.enable_iam ? "AWS_IAM" : "NONE" — unknown at plan time
        authorization: null,
      },
    } as unknown as TerraformResource;

    expect(scan(method)).toBeNull();
  });

  it('returns no finding when a non-OPTIONS HTTP API route authorization_type is unresolved (null) at plan time', () => {
    const route: TerraformResource = {
      type: 'aws_apigatewayv2_route',
      name: 'get_items',
      address: 'aws_apigatewayv2_route.get_items',
      values: {
        api_id: 'aws_apigatewayv2_api.http_api',
        route_key: 'GET /items',
        authorization_type: null,
      },
    } as unknown as TerraformResource;

    expect(scan(route)).toBeNull();
  });

  // Opposite outcome: identical fixture except the authorization value is determinate
  // and non-compliant — the rule must flag it.
  it('flags a non-OPTIONS REST method whose authorization resolves to the literal NONE', () => {
    const method: TerraformResource = {
      type: 'aws_api_gateway_method',
      name: 'get_items',
      address: 'aws_api_gateway_method.get_items',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        http_method: 'GET',
        authorization: 'NONE',
      },
    } as unknown as TerraformResource;

    const result = scan(method);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
  });
});
