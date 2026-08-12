import { describe, it, expect } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002TfAdapterFactory();

const validator: TerraformResource = {
  type: 'aws_api_gateway_request_validator',
  name: 'v',
  address: 'aws_api_gateway_request_validator.v',
  values: {
    name: 'body-validator',
    rest_api_id: 'aws_api_gateway_rest_api.api',
    validate_request_body: true,
    validate_request_parameters: true,
  },
} as unknown as TerraformResource;

function buildMethod(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_api_gateway_method',
    name: 'post_items',
    address: 'aws_api_gateway_method.post_items',
    values,
  } as unknown as TerraformResource;
}

function run(method: TerraformResource) {
  const allResources = [method, validator];
  const context: TfContext = {
    projectName: 'test-project',
    resource: method,
    allResources,
  };
  return apigw002Control.run(factory.bind(context) as never, context);
}

describe('APIGW-002 REQ-01 (Terraform): method with no request validator reference', () => {
  it('flags a non-preflight method that references no request validator', () => {
    const result = run(
      buildMethod({
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'POST',
        authorization: 'NONE',
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceType).toBe('aws_api_gateway_method');
    expect(result?.resourceName).toBe('aws_api_gateway_method.post_items');
  });

  // Opposite outcome: nearest input that flips the verdict — the same method WITH a
  // request_validator_id, given in reference form (collapsed to the validator address).
  // Primary behavior (validator present => pass) is owned by the sibling requirement.
  it('does not flag the same method when it references a request validator', () => {
    const result = run(
      buildMethod({
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.items',
        http_method: 'POST',
        authorization: 'NONE',
        request_models: { 'application/json': 'Model' },
        request_validator_id: 'aws_api_gateway_request_validator.v',
      }),
    );

    expect(result).toBeNull();
  });
});
