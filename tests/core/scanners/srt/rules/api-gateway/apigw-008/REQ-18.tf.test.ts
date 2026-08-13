import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

// REQ-18 (APIGW-008): A catch-all method setting (method_path "*" over "*") that enables
// cache_data_encrypted covers every cached method. A per-method setting that enables
// caching without stating an encryption value inherits encryption from the catch-all
// and must NOT be flagged.

const factory = new Apigw008TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'this',
  address: 'aws_api_gateway_stage.this',
  values: { stage_name: 'prod', rest_api_id: 'aws_api_gateway_rest_api.this' },
} as unknown as TerraformResource;

// Reference form — HCL wrote `stage_name = aws_api_gateway_stage.this.stage_name`
const catchAllEncrypted: TerraformResource = {
  type: 'aws_api_gateway_method_settings',
  name: 'catch_all',
  address: 'aws_api_gateway_method_settings.catch_all',
  values: {
    stage_name: 'aws_api_gateway_stage.this',
    method_path: '*/*',
    settings: [{ caching_enabled: true, cache_data_encrypted: true }],
  },
} as unknown as TerraformResource;

function perMethod(settings: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'items_get',
    address: 'aws_api_gateway_method_settings.items_get',
    values: {
      stage_name: 'aws_api_gateway_stage.this',
      method_path: 'items/GET',
      settings: [settings],
    },
  } as unknown as TerraformResource;
}

function runControl(resource: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  return apigw008Control.run(factory.bind(context), context);
}

describe('APIGW-008 REQ-18 (Terraform)', () => {
  it('passes for the stage when a method enables caching without an encryption value and a catch-all enables cache data encryption', () => {
    const perMethodNoEncryptionValue = perMethod({ caching_enabled: true });
    const all = [stage, catchAllEncrypted, perMethodNoEncryptionValue];

    expect(runControl(stage, all)).toBeNull();
  });

  it('passes for the per-method settings resource itself, which inherits encryption from the catch-all', () => {
    const perMethodNoEncryptionValue = perMethod({ caching_enabled: true });
    const all = [stage, catchAllEncrypted, perMethodNoEncryptionValue];

    expect(runControl(perMethodNoEncryptionValue, all)).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict is the same
  // per-method setting stating cache_data_encrypted explicitly as false.
  it('flags when a cached method explicitly sets cache_data_encrypted to false despite the encrypted catch-all', () => {
    const perMethodUnencrypted = perMethod({ caching_enabled: true, cache_data_encrypted: false });
    const all = [stage, catchAllEncrypted, perMethodUnencrypted];

    const result = runControl(stage, all);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
  });
});
