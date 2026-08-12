import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.tf.js';
import type { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002TfAdapterFactory();

const enabledValidator: TerraformResource = {
  type: 'aws_api_gateway_request_validator',
  name: 'enabled',
  address: 'aws_api_gateway_request_validator.enabled',
  values: {
    name: 'body-validator',
    rest_api_id: 'aws_api_gateway_rest_api.api',
    validate_request_body: true,
    validate_request_parameters: false,
  },
} as TerraformResource;

// Reference form: HCL wrote aws_api_gateway_request_validator.enabled.id
const siblingMethod: TerraformResource = {
  type: 'aws_api_gateway_method',
  name: 'sibling',
  address: 'aws_api_gateway_method.sibling',
  values: {
    http_method: 'POST',
    rest_api_id: 'aws_api_gateway_rest_api.api',
    resource_id: 'aws_api_gateway_resource.item',
    authorization: 'AWS_IAM',
    request_models: { 'application/json': 'Model' },
    request_validator_id: 'aws_api_gateway_request_validator.enabled',
  },
} as TerraformResource;

function assessedMethod(requestValidatorId?: unknown): TerraformResource {
  const values: Record<string, unknown> = {
    http_method: 'POST',
    rest_api_id: 'aws_api_gateway_rest_api.api',
    resource_id: 'aws_api_gateway_resource.item',
    authorization: 'AWS_IAM',
    request_models: { 'application/json': 'Model' },
  };
  if (requestValidatorId !== undefined) values['request_validator_id'] = requestValidatorId;
  return {
    type: 'aws_api_gateway_method',
    name: 'assessed',
    address: 'aws_api_gateway_method.assessed',
    values,
  } as TerraformResource;
}

function assess(resource: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context) as Apigw002Adapter;
  return apigw002Control.run(adapter, context);
}

describe('APIGW-002 REQ-08 (Terraform): validator on a sibling method does not validate the assessed method', () => {
  // Primary behavior owned by APIGW-002: request validation is per-method.
  it('flags the assessed method when the enabled validator is only referenced by a sibling method', () => {
    const assessed = assessedMethod(undefined);
    const result = assess(assessed, [enabledValidator, siblingMethod, assessed]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('aws_api_gateway_method.assessed');
    expect(result?.resourceType).toBe('aws_api_gateway_method');
  });

  it('does not flag the sibling method that itself references the enabled validator (reference form)', () => {
    const assessed = assessedMethod(undefined);
    const result = assess(siblingMethod, [enabledValidator, siblingMethod, assessed]);

    expect(result).toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict — the assessed method
  // references the same enabled validator instead of none.
  it('does not flag when the assessed method itself references the enabled validator (reference form)', () => {
    const assessed = assessedMethod('aws_api_gateway_request_validator.enabled');
    const result = assess(assessed, [enabledValidator, siblingMethod, assessed]);

    expect(result).toBeNull();
  });
});
