import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import type { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002TfAdapterFactory();

function scan(method: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource: method, allResources };
  const adapter = factory.bind(context) as Apigw002Adapter;
  return apigw002Control.run(adapter, context);
}

// Validator with validation enabled, attached (by reference) to a different API.
const validatorForApiB: TerraformResource = {
  type: 'aws_api_gateway_request_validator',
  name: 'for_api_b',
  address: 'aws_api_gateway_request_validator.for_api_b',
  values: {
    name: 'validator-for-api-b',
    rest_api_id: 'aws_api_gateway_rest_api.api_b',
    validate_request_body: true,
    validate_request_parameters: true,
  },
} as TerraformResource;

const methodOnApiA: TerraformResource = {
  type: 'aws_api_gateway_method',
  name: 'post_on_api_a',
  address: 'aws_api_gateway_method.post_on_api_a',
  values: {
    rest_api_id: 'aws_api_gateway_rest_api.api_a',
    resource_id: 'aws_api_gateway_resource.res_a',
    http_method: 'POST',
    authorization: 'NONE',
    // no request_validator_id — the unrelated validator on api_b is not referenced
  },
} as TerraformResource;

/**
 * REQ-07 (primary behavior owned by APIGW-002): a request validator with validation
 * enabled that belongs to a DIFFERENT API provides no coverage for the assessed
 * method, so the method must still be flagged.
 */
describe('APIGW-002 Terraform — validator with validation enabled belongs to a different API', () => {
  it('flags the method when the only enabled validator in the plan belongs to another API and is not referenced', () => {
    const result = scan(methodOnApiA, [methodOnApiA, validatorForApiB]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('aws_api_gateway_method.post_on_api_a');
    expect(result?.resourceType).toBe('aws_api_gateway_method');
  });

  // Opposite outcome: nearest input that flips the verdict — the method references
  // (reference form) an enabled validator belonging to its OWN API.
  it('does not flag the method when it references an enabled validator belonging to its own API', () => {
    const validatorForApiA: TerraformResource = {
      type: 'aws_api_gateway_request_validator',
      name: 'for_api_a',
      address: 'aws_api_gateway_request_validator.for_api_a',
      values: {
        name: 'validator-for-api-a',
        rest_api_id: 'aws_api_gateway_rest_api.api_a',
        validate_request_body: true,
        validate_request_parameters: true,
      },
    } as TerraformResource;

    const method: TerraformResource = {
      ...methodOnApiA,
      values: {
        ...(methodOnApiA.values as Record<string, unknown>),
        request_models: { 'application/json': 'Model' },
        request_validator_id: 'aws_api_gateway_request_validator.for_api_a',
      },
    } as TerraformResource;

    const result = scan(method, [method, validatorForApiB, validatorForApiA]);

    expect(result).toBeNull();
  });
});
