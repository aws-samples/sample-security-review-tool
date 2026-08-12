import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002TfAdapterFactory();

/** Request validator whose configuration enables request body validation. */
const bodyValidator: TerraformResource = {
  type: 'aws_api_gateway_request_validator',
  name: 'body',
  address: 'aws_api_gateway_request_validator.body',
  values: {
    name: 'body-validator',
    rest_api_id: 'aws_api_gateway_rest_api.api',
    validate_request_body: true,
    validate_request_parameters: false,
  },
} as unknown as TerraformResource;

function method(requestValidatorId: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method',
    name: 'post',
    address: 'aws_api_gateway_method.post',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      resource_id: 'aws_api_gateway_resource.item',
      http_method: 'POST',
      authorization: 'AWS_IAM',
      request_models: { 'application/json': 'Model' },
      request_validator_id: requestValidatorId,
    },
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource, bodyValidator],
  };
  return apigw002Control.run(factory.bind(context), context);
}

describe('APIGW-002 (Terraform) - method references a request validator that validates the request body', () => {
  // Primary behaviour owned by this requirement (REQ-02) - reference form.
  it('passes when the method references the body-validating validator by resource address', () => {
    const result = run(method(bodyValidator.address));

    expect(result).toBeNull();
  });

  // Primary behaviour owned by this requirement (REQ-02) - literal form.
  it('passes when the method references the body-validating validator by literal id', () => {
    const result = run(method('abc123'));

    expect(result).toBeNull();
  });

  // Opposite outcome: request_validator_id is present but empty, so it references
  // no validator and no request validation is enforced.
  it('flags the method when request_validator_id is present but empty, referencing no validator', () => {
    const result = run(method(''));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('aws_api_gateway_method.post');
    expect(result?.resourceType).toBe('aws_api_gateway_method');
  });
});
