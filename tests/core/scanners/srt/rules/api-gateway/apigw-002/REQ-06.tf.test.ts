import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import type { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

// REQ-06 (owner of this behavior): an API method whose request_validator_id is
// empty/blank identifies no validator, so it must be flagged exactly like a method
// with no validation at all.

const factory = new Apigw002TfAdapterFactory();

const enforcingValidator: TerraformResource = {
  type: 'aws_api_gateway_request_validator',
  name: 'body',
  address: 'aws_api_gateway_request_validator.body',
  values: {
    name: 'body-validator',
    validate_request_body: true,
    validate_request_parameters: false,
  },
} as unknown as TerraformResource;

function buildMethod(validatorId: unknown): TerraformResource {
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
      request_validator_id: validatorId,
    },
  } as unknown as TerraformResource;
}

function run(validatorId: unknown): ScanResult | null {
  const method = buildMethod(validatorId);
  const context: TfContext = {
    projectName: 'test-project',
    resource: method,
    allResources: [method, enforcingValidator],
  };
  const adapter = factory.bind(context) as Apigw002Adapter;
  return apigw002Control.run(adapter, context);
}

describe('APIGW-002 REQ-06 (Terraform): blank request validator reference', () => {
  it('flags a method whose request_validator_id is an empty string', () => {
    const result = run('');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('aws_api_gateway_method.post');
    expect(result?.resourceType).toBe('aws_api_gateway_method');
  });

  it('flags a method whose request_validator_id is whitespace only', () => {
    const result = run('   ');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // Opposite outcome, reference form: same method, but the validator reference is
  // present and non-blank, collapsing to the validator resource address.
  it('does not flag a method whose request_validator_id references a real enforcing validator', () => {
    const result = run('aws_api_gateway_request_validator.body');
    expect(result).toBeNull();
  });
});
