import { describe, it, expect } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import type { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002TfAdapterFactory();

function buildValidator(validateBody: boolean, validateParameters: boolean): TerraformResource {
  return {
    type: 'aws_api_gateway_request_validator',
    name: 'params_only',
    address: 'aws_api_gateway_request_validator.params_only',
    values: {
      name: 'params-only-validator',
      rest_api_id: 'aws_api_gateway_rest_api.api',
      validate_request_body: validateBody,
      validate_request_parameters: validateParameters,
    },
  } as TerraformResource;
}

/** Body-accepting POST method; request_validator_id is in reference form (collapsed address). */
const method: TerraformResource = {
  type: 'aws_api_gateway_method',
  name: 'post_order',
  address: 'aws_api_gateway_method.post_order',
  values: {
    rest_api_id: 'aws_api_gateway_rest_api.api',
    resource_id: 'aws_api_gateway_resource.orders',
    http_method: 'POST',
    authorization: 'AWS_IAM',
    // Method accepts a request body
    request_models: { 'application/json': 'OrderModel' },
    request_parameters: {
      'method.request.querystring.tenantId': true,
      'method.request.header.X-Correlation-Id': true,
    },
    request_models: { 'application/json': 'Model' },
    request_validator_id: 'aws_api_gateway_request_validator.params_only',
  },
} as TerraformResource;

function run(validator: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: method,
    allResources: [method, validator],
  };
  const adapter = factory.bind(context) as Apigw002Adapter;
  return apigw002Control.run(adapter, context);
}

describe('APIGW-002 (Terraform) - parameter-only validation on a body-accepting method', () => {
  // Primary behavior owned by APIGW-002: body OR query/header parameter validation satisfies the rule.
  it('passes when a body-accepting method uses a validator that only validates query string and header parameters', () => {
    expect(run(buildValidator(false, true))).toBeNull();
  });

  // Opposite outcome: same method, but the validator enforces neither body nor parameter validation.
  it('flags the same method when the referenced validator validates neither body nor parameters', () => {
    const result = run(buildValidator(false, false));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('aws_api_gateway_method.post_order');
  });
});
