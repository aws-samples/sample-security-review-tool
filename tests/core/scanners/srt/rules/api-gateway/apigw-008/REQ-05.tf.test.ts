import { describe, it, expect } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (APIGW-008): Caching is enabled only for one specific method and path,
 * and that same specific setting also enables cache data encryption -> PASS.
 */

const factory = new Apigw008TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: { stage_name: 'prod', rest_api_id: 'aws_api_gateway_rest_api.pets' },
} as unknown as TerraformResource;

function methodSettings(cacheDataEncrypted: boolean): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'pets_get',
    address: 'aws_api_gateway_method_settings.pets_get',
    values: {
      // reference form: written in HCL as aws_api_gateway_stage.prod.stage_name
      rest_api_id: 'aws_api_gateway_rest_api.pets',
      stage_name: 'aws_api_gateway_stage.prod',
      method_path: 'pets/GET',
      settings: [
        {
          caching_enabled: true,
          cache_data_encrypted: cacheDataEncrypted,
        },
      ],
    },
  } as unknown as TerraformResource;
}

function runControl(resource: TerraformResource) {
  const allResources = [stage, resource];
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 REQ-05 (Terraform)', () => {
  it('passes when the only method path with caching enabled also has cache_data_encrypted = true', () => {
    expect(runControl(methodSettings(true))).toBeNull();
  });

  // Opposite outcome: same single cached method path, encryption present but false -> must flag.
  it('flags when that same specific cached method path has cache_data_encrypted = false', () => {
    const result = runControl(methodSettings(false));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
  });
});
