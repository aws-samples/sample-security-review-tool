import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import type { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (APIGW-002): A method that references an existing request validator which
 * specifies NO validation flags at all must be flagged — both validate_request_body and
 * validate_request_parameters default to false, so the validator validates nothing.
 */

const factory = new Apigw002TfAdapterFactory();

function validator(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_api_gateway_request_validator',
    name: 'v',
    address: 'aws_api_gateway_request_validator.v',
    values,
  } as TerraformResource;
}

function method(requestValidatorId: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method',
    name: 'post',
    address: 'aws_api_gateway_method.post',
    values: {
      http_method: 'POST',
      authorization: 'AWS_IAM',
      rest_api_id: 'aws_api_gateway_rest_api.api',
      resource_id: 'aws_api_gateway_resource.item',
      request_models: { 'application/json': 'Model' },
      request_validator_id: requestValidatorId,
    },
  } as TerraformResource;
}

function run(methodResource: TerraformResource, validatorResource: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: methodResource,
    allResources: [methodResource, validatorResource],
  };
  const adapter = factory.bind(context) as Apigw002Adapter;
  return apigw002Control.run(adapter, context);
}

describe('APIGW-002 REQ-05 (Terraform): referenced validator with no validation flags', () => {
  it('flags a method referencing (by address) a validator that omits both validation flags', () => {
    const validatorResource = validator({ name: 'no-flags-validator' });
    const result = run(method(validatorResource.address), validatorResource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('aws_api_gateway_method.post');
    expect(result?.resourceType).toBe('aws_api_gateway_method');
  });

  it('flags a method referencing a validator by literal name that omits both validation flags', () => {
    const validatorResource = validator({ name: 'no-flags-validator' });
    const result = run(method('no-flags-validator'), validatorResource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // Opposite outcome: the nearest input that flips the verdict — same referenced validator,
  // but it actually enables body validation.
  it('does not flag a method whose referenced validator enables body validation', () => {
    const validatorResource = validator({ name: 'body-validator', validate_request_body: true });
    const result = run(method(validatorResource.address), validatorResource);

    expect(result).toBeNull();
  });
});
