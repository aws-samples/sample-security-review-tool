import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-11 (APIGW-002): when the effective request-validation configuration depends on a
 * condition that cannot be determined at analysis time (plan-time unknown values), the
 * rule must return no finding. The opposite-outcome test at the bottom belongs to the
 * primary APIGW-002 behaviour and keeps this file discriminating.
 */

const factory = new Apigw002TfAdapterFactory();

function run(resource: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  return apigw002Control.run(factory.bind(context), context);
}

function method(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_api_gateway_method',
    name: 'post_items',
    address: 'aws_api_gateway_method.post_items',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      resource_id: 'aws_api_gateway_resource.items',
      http_method: 'POST',
      ...values,
    },
  } as unknown as TerraformResource;
}

describe('APIGW-002 REQ-11 (Terraform): undeterminable validation configuration', () => {
  it('returns no finding when the referenced validator flags are unknown at plan time (reference form)', () => {
    const validator: TerraformResource = {
      type: 'aws_api_gateway_request_validator',
      name: 'conditional',
      address: 'aws_api_gateway_request_validator.conditional',
      values: {
        name: 'conditional',
        rest_api_id: 'aws_api_gateway_rest_api.api',
        // Both driven by a variable/conditional the plan cannot resolve.
        validate_request_body: null,
        validate_request_parameters: null,
      },
    } as unknown as TerraformResource;

    const target = method({ request_validator_id: 'aws_api_gateway_request_validator.conditional' });

    expect(run(target, [target, validator])).toBeNull();
  });

  it('returns no finding when the referenced validator flags are unknown at plan time (literal name form)', () => {
    const validator: TerraformResource = {
      type: 'aws_api_gateway_request_validator',
      name: 'conditional',
      address: 'aws_api_gateway_request_validator.conditional',
      values: {
        name: 'conditional-validator',
        rest_api_id: 'aws_api_gateway_rest_api.api',
        validate_request_body: null,
        validate_request_parameters: null,
      },
    } as unknown as TerraformResource;

    const target = method({ request_validator_id: 'conditional-validator' });

    expect(run(target, [target, validator])).toBeNull();
  });

  // OPPOSITE OUTCOME — owned by the primary APIGW-002 behaviour: identical wiring, but the
  // validator flags are determinable and both disabled, so the method must be flagged.
  it('flags the method when the referenced validator determinably enforces nothing', () => {
    const validator: TerraformResource = {
      type: 'aws_api_gateway_request_validator',
      name: 'conditional',
      address: 'aws_api_gateway_request_validator.conditional',
      values: {
        name: 'conditional',
        rest_api_id: 'aws_api_gateway_rest_api.api',
        validate_request_body: false,
        validate_request_parameters: false,
      },
    } as unknown as TerraformResource;

    const target = method({ request_validator_id: 'aws_api_gateway_request_validator.conditional' });

    const result = run(target, [target, validator]);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });
});
