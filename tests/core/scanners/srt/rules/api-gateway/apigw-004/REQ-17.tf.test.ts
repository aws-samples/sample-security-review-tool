import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-17 (APIGW-004): A non-OPTIONS method with no authorization must be flagged even when the
 * parent REST API has an aws_api_gateway_rest_api_policy restricting callers. The resource policy is
 * an optional origin-based control, not identity-based authorization.
 */

const restApi: TerraformResource = {
  type: 'aws_api_gateway_rest_api',
  name: 'api',
  address: 'aws_api_gateway_rest_api.api',
  values: { name: 'policy-protected-api' },
} as unknown as TerraformResource;

const restApiPolicy: TerraformResource = {
  type: 'aws_api_gateway_rest_api_policy',
  name: 'api',
  address: 'aws_api_gateway_rest_api_policy.api',
  values: {
    // Reference form: rest_api_id = aws_api_gateway_rest_api.api.id
    rest_api_id: 'aws_api_gateway_rest_api.api',
    policy:
      '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*","Condition":{"IpAddress":{"aws:SourceIp":["192.0.2.0/24"]}}}]}',
  },
} as unknown as TerraformResource;

const apiResource: TerraformResource = {
  type: 'aws_api_gateway_resource',
  name: 'items',
  address: 'aws_api_gateway_resource.items',
  values: { rest_api_id: 'aws_api_gateway_rest_api.api', path_part: 'items' },
} as unknown as TerraformResource;

function buildMethod(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_api_gateway_method',
    name: 'get_items',
    address: 'aws_api_gateway_method.get_items',
    values: {
      // Reference form: rest_api_id = aws_api_gateway_rest_api.api.id
      rest_api_id: 'aws_api_gateway_rest_api.api',
      resource_id: 'aws_api_gateway_resource.items',
      http_method: 'GET',
      ...values,
    },
  } as unknown as TerraformResource;
}

function runControl(method: TerraformResource) {
  const allResources = [restApi, restApiPolicy, apiResource, method];
  const context: TfContext = { projectName: 'test-project', resource: method, allResources };
  const factory = new Apigw004TfAdapterFactory();
  expect(factory.appliesTo(method.type)).toBe(true);
  return apigw004Control.run(factory.bind(context), context);
}

describe('APIGW-004 REQ-17 (Terraform): API-level resource policy does not substitute for method authorization', () => {
  it('flags a non-OPTIONS method with no authorization even though the API has a restrictive resource policy', () => {
    const result = runControl(buildMethod({}));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceType).toBe('aws_api_gateway_method');
    expect(result?.resourceName).toBe('aws_api_gateway_method.get_items');
  });

  // Opposite outcome: the requirement turns on the method's authorization setting, so the nearest
  // input that flips the verdict is the same policy-protected API method with AWS_IAM authorization.
  it('does not flag when the same policy-protected API method sets authorization to AWS_IAM', () => {
    const result = runControl(buildMethod({ authorization: 'AWS_IAM' }));

    expect(result).toBeNull();
  });
});
