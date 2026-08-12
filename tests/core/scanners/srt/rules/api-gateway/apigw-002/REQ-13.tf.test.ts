import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (APIGW-002): A method that references a validator which enables ONLY parameter
 * validation, while the method declares no REQUIRED query string / header parameters,
 * must be flagged — parameter validation only checks required parameters, so nothing is
 * actually enforced.
 */

const factory = new Apigw002TfAdapterFactory();

/** Validator that validates parameters only (body validation off). */
const parametersOnlyValidator: TerraformResource = {
  type: 'aws_api_gateway_request_validator',
  name: 'params_only',
  address: 'aws_api_gateway_request_validator.params_only',
  values: {
    name: 'params-only',
    rest_api_id: 'aws_api_gateway_rest_api.api',
    validate_request_body: false,
    validate_request_parameters: true,
  },
} as unknown as TerraformResource;

function buildMethod(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_api_gateway_method',
    name: 'post',
    address: 'aws_api_gateway_method.post',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      resource_id: 'aws_api_gateway_resource.item',
      http_method: 'POST',
      authorization: 'AWS_IAM',
      ...values,
    },
  } as unknown as TerraformResource;
}

function run(method: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: method,
    allResources: [method, parametersOnlyValidator],
  };
  return apigw002Control.run(factory.bind(context), context);
}

describe('APIGW-002 REQ-13 (Terraform): parameter-only validator with nothing required', () => {
  it('flags a method (reference form) whose parameter-only validator has no declared request parameters', () => {
    const result = run(
      buildMethod({
        // request_validator_id = aws_api_gateway_request_validator.params_only.id
        request_models: { 'application/json': 'Model' },
        request_validator_id: 'aws_api_gateway_request_validator.params_only',
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('aws_api_gateway_method.post');
  });

  it('flags a method (literal name form) whose declared query string and header parameters are all optional', () => {
    const result = run(
      buildMethod({
        request_models: { 'application/json': 'Model' },
        request_validator_id: 'params-only',
        request_parameters: {
          'method.request.querystring.search': false,
          'method.request.header.X-Trace': false,
        },
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // Opposite outcome: the nearest input that flips the verdict — the same parameter is
  // present but marked REQUIRED, so parameter validation actually enforces something.
  it('does not flag a method that declares a required query string parameter', () => {
    const result = run(
      buildMethod({
        request_models: { 'application/json': 'Model' },
        request_validator_id: 'aws_api_gateway_request_validator.params_only',
        request_parameters: {
          'method.request.querystring.search': true,
          'method.request.header.X-Trace': false,
        },
      }),
    );

    expect(result).toBeNull();
  });

  // Opposite outcome: a required header parameter is equally sufficient.
  it('does not flag a method that declares a required header parameter', () => {
    const result = run(
      buildMethod({
        request_models: { 'application/json': 'Model' },
        request_validator_id: 'aws_api_gateway_request_validator.params_only',
        request_parameters: {
          'method.request.header.X-Trace': true,
        },
      }),
    );

    expect(result).toBeNull();
  });
});
