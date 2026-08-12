import { describe, it, expect } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (APIGW-002): A CORS preflight method (OPTIONS) with no request validation
 * configured must PASS — preflight requests carry no body and are explicitly excluded.
 */

const factory = new Apigw002TfAdapterFactory();

function buildMethod(httpMethod: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method',
    name: 'preflight',
    address: 'aws_api_gateway_method.preflight',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      resource_id: 'aws_api_gateway_resource.items',
      http_method: httpMethod,
      authorization: 'NONE',
      // no request_validator_id configured
    },
  } as unknown as TerraformResource;
}

const restApi = {
  type: 'aws_api_gateway_rest_api',
  name: 'api',
  address: 'aws_api_gateway_rest_api.api',
  values: { name: 'test-api' },
} as unknown as TerraformResource;

function run(httpMethod: string) {
  const method = buildMethod(httpMethod);
  const context: TfContext = {
    projectName: 'test-project',
    resource: method,
    allResources: [method, restApi],
  };
  return apigw002Control.run(factory.bind(context), context);
}

describe('APIGW-002 REQ-10 (Terraform): CORS preflight method exclusion', () => {
  it('passes an OPTIONS (CORS preflight) method that has no request validator', () => {
    expect(run('OPTIONS')).toBeNull();
  });

  it('passes an options (lower-cased preflight verb) method that has no request validator', () => {
    expect(run('options')).toBeNull();
  });

  // Opposite outcome: identical fixture, only the verb changes to a non-preflight verb.
  // The finding itself is owned by the "no request validator" requirement; asserted here
  // only to prove the preflight exclusion is what makes the OPTIONS case pass.
  it('flags a non-preflight POST method that has no request validator', () => {
    const result = run('POST');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('aws_api_gateway_method.preflight');
  });
});
