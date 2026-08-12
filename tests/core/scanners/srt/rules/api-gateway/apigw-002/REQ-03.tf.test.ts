import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import type { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002TfAdapterFactory();

interface ValidatorConfig {
  readonly validate_request_body: boolean;
  readonly validate_request_parameters: boolean;
}

function validatorResource(config: ValidatorConfig): TerraformResource {
  return {
    type: 'aws_api_gateway_request_validator',
    name: 'validator',
    address: 'aws_api_gateway_request_validator.validator',
    values: {
      name: 'params-validator',
      rest_api_id: 'aws_api_gateway_rest_api.api',
      validate_request_body: config.validate_request_body,
      validate_request_parameters: config.validate_request_parameters,
    },
  } as unknown as TerraformResource;
}

function methodResource(validatorId: string): TerraformResource {
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
      request_validator_id: validatorId,
      request_parameters: {
        'method.request.querystring.customerId': true,
        'method.request.header.x-correlation-id': true,
      },
    },
  } as unknown as TerraformResource;
}

function run(method: TerraformResource, others: TerraformResource[]) {
  const allResources = [method, ...others];
  const context: TfContext = { projectName: 'test-project', resource: method, allResources };
  const adapter = factory.bind(context) as Apigw002Adapter;
  return apigw002Control.run(adapter, context);
}

describe('APIGW-002 REQ-03 (Terraform): parameter-only request validator', () => {
  // Primary behavior owned by this requirement: body OR query/header parameter
  // validation satisfies the rule.
  it('passes when the referenced validator validates required query/header parameters but not the body (reference form)', () => {
    const validator = validatorResource({ validate_request_body: false, validate_request_parameters: true });
    const method = methodResource(validator.address);

    expect(run(method, [validator])).toBeNull();
  });

  it('passes when the validator is wired by literal name and validates parameters only (literal form)', () => {
    const validator = validatorResource({ validate_request_body: false, validate_request_parameters: true });
    const method = methodResource('params-validator');

    expect(run(method, [validator])).toBeNull();
  });

  it('passes when the referenced validator validates the request body but not parameters', () => {
    const validator = validatorResource({ validate_request_body: true, validate_request_parameters: false });
    const method = methodResource(validator.address);

    expect(run(method, [validator])).toBeNull();
  });

  // Opposite outcome: validator still referenced, but it enforces neither body
  // nor parameter validation.
  it('flags a method whose referenced validator validates neither the body nor parameters', () => {
    const validator = validatorResource({ validate_request_body: false, validate_request_parameters: false });
    const method = methodResource(validator.address);

    const result = run(method, [validator]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('aws_api_gateway_method.post');
  });
});
