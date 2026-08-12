import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002TfAdapterFactory();

function method(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_api_gateway_method',
    name: 'wildcard',
    address: 'aws_api_gateway_method.wildcard',
    values,
  } as unknown as TerraformResource;
}

function scan(resource: TerraformResource, allResources: TerraformResource[] = []) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource, ...allResources],
  };
  const adapter = factory.bind(context) as Apigw002Adapter;
  return apigw002Control.run(adapter, context);
}

describe('APIGW-002 (Terraform) — wildcard ANY method without request validation', () => {
  // Primary behavior owned by APIGW-002: an ANY/wildcard method accepts body-bearing
  // verbs, so the CORS preflight exclusion does not apply to it.
  it('flags an ANY method with no request_validator_id', () => {
    const result = scan(
      method({
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.res',
        http_method: 'ANY',
        authorization: 'NONE',
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('aws_api_gateway_method.wildcard');
  });

  it('flags a lower-cased "any" wildcard method with no request_validator_id', () => {
    const result = scan(
      method({
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.res',
        http_method: 'any',
        authorization: 'NONE',
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // Opposite outcome: identical wildcard method, but a validator reference IS present
  // and that validator enforces body validation. Reference form (address string).
  it('does not flag an ANY method referencing a validator that enforces body validation', () => {
    const validator: TerraformResource = {
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

    const result = scan(
      method({
        rest_api_id: 'aws_api_gateway_rest_api.api',
        resource_id: 'aws_api_gateway_resource.res',
        http_method: 'ANY',
        authorization: 'NONE',
        request_models: { 'application/json': 'Model' },
        request_validator_id: 'aws_api_gateway_request_validator.body',
      }),
      [validator],
    );

    expect(result).toBeNull();
  });
});
