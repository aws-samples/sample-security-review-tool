import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-16 (APIGW-002): A method that enables body validation while declaring no request body model
 * must be flagged — API Gateway performs no payload validation when no model matches the request
 * content type, so the flag alone enforces nothing.
 */

const factory = new Apigw002TfAdapterFactory();

function validator(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_api_gateway_request_validator',
    name: 'validator',
    address: 'aws_api_gateway_request_validator.validator',
    values: { name: 'validator', rest_api_id: 'aws_api_gateway_rest_api.api', ...values },
  } as unknown as TerraformResource;
}

function method(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_api_gateway_method',
    name: 'assessed',
    address: 'aws_api_gateway_method.assessed',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      resource_id: 'aws_api_gateway_resource.item',
      authorization: 'AWS_IAM',
      http_method: 'POST',
      request_validator_id: 'aws_api_gateway_request_validator.validator',
      ...values,
    },
  } as unknown as TerraformResource;
}

function run(methodValues: Record<string, unknown>, validatorValues: Record<string, unknown>) {
  const resource = method(methodValues);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource, validator(validatorValues)],
  };
  return apigw002Control.run(factory.bind(context), context);
}

const bodyOnly = { validate_request_body: true, validate_request_parameters: false };
const bodyAndParameters = { validate_request_body: true, validate_request_parameters: true };

describe('APIGW-002 REQ-16 (Terraform): body validation with no model declared', () => {
  it('flags a method that enables body validation but declares no request body model', () => {
    const result = run({}, bodyOnly);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('aws_api_gateway_method.assessed');
  });

  it('flags a method whose declared request body model map is empty', () => {
    const result = run({ request_models: {} }, bodyOnly);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // Parameter validation alone cannot rescue it while nothing is marked required.
  it('flags a method with body and parameter validation whose parameters are all optional', () => {
    const result = run({ request_parameters: { 'method.request.header.X-Trace': false } }, bodyAndParameters);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // Opposite outcome: the nearest input that flips the verdict — the same method now declares a
  // model, so the enabled body validation has a schema to enforce.
  it('does not flag the same method once it declares a request body model', () => {
    const result = run({ request_models: { 'application/json': 'Model' } }, bodyOnly);

    expect(result).toBeNull();
  });

  // Enforced parameter validation is sufficient on its own, model or not.
  it('does not flag when a required parameter is validated alongside the unusable body flag', () => {
    const result = run({ request_parameters: { 'method.request.querystring.search': true } }, bodyAndParameters);

    expect(result).toBeNull();
  });
});
