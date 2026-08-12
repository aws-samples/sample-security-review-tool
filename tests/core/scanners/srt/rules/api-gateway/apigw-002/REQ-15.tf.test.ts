import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-15 (APIGW-002): A method whose verb carries no request body by definition, declaring no
 * body model and no query string or header parameters, must pass even with no request validator.
 */

const factory = new Apigw002TfAdapterFactory();

function method(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_api_gateway_method',
    name: 'assessed',
    address: 'aws_api_gateway_method.assessed',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      resource_id: 'aws_api_gateway_resource.item',
      authorization: 'AWS_IAM',
      ...values,
    },
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  return apigw002Control.run(factory.bind(context), context);
}

describe('APIGW-002 REQ-15 (Terraform): a method with no declared input needs no validator', () => {
  it('passes a GET that declares no body model and no parameters', () => {
    const result = run(method({ http_method: 'GET' }));

    expect(result).toBeNull();
  });

  it('passes a HEAD that declares no body model and no parameters', () => {
    const result = run(method({ http_method: 'HEAD' }));

    expect(result).toBeNull();
  });

  it('passes a DELETE that declares no body model and no parameters', () => {
    const result = run(method({ http_method: 'DELETE' }));

    expect(result).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict — the same GET declares a
  // parameter, so a validator could enforce something and its absence is a real finding.
  it('flags the same GET once it declares a query string parameter', () => {
    const result = run(
      method({
        http_method: 'GET',
        request_parameters: { 'method.request.querystring.search': true },
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('aws_api_gateway_method.assessed');
  });

  // A declared body model is also input, even on a verb whose body has no defined semantics.
  it('flags the same GET once it declares a request body model', () => {
    const result = run(
      method({
        http_method: 'GET',
        request_models: { 'application/json': 'Model' },
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // A path parameter is validatable input too: validation covers required parameters in the URI.
  it('flags the same GET when it declares only a required path parameter', () => {
    const result = run(
      method({
        http_method: 'GET',
        request_parameters: { 'method.request.path.proxy': true },
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // A body-carrying verb is never exempt: declaring a model and validating it is a real fix.
  it('flags a POST that declares nothing, because a body can still arrive', () => {
    const result = run(method({ http_method: 'POST' }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });
});
