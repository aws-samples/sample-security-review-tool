import { describe, it, expect } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-02 (APIGW-008): A catch-all aws_api_gateway_method_settings block ("*&#47;*")
 * that enables caching AND cache_data_encrypted covers every method of the stage
 * -> pass (no finding).
 */

const factory = new Apigw008TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    stage_name: 'prod',
    rest_api_id: 'aws_api_gateway_rest_api.this',
    cache_cluster_enabled: true,
    cache_cluster_size: '0.5',
  },
} as unknown as TerraformResource;

function catchAllSettings(cacheDataEncrypted: unknown): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'all',
    address: 'aws_api_gateway_method_settings.all',
    values: {
      // reference form: stage_name = aws_api_gateway_stage.prod.stage_name
      rest_api_id: 'aws_api_gateway_rest_api.this',
      stage_name: 'aws_api_gateway_stage.prod',
      method_path: '*/*',
      settings: [
        {
          caching_enabled: true,
          cache_data_encrypted: cacheDataEncrypted,
        },
      ],
    },
  } as unknown as TerraformResource;
}

function runControl(resource: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 REQ-02 (Terraform): catch-all caching with cache_data_encrypted', () => {
  it('passes when the catch-all method settings enable caching and cache_data_encrypted', () => {
    const settings = catchAllSettings(true);
    expect(runControl(settings, [stage, settings])).toBeNull();
  });

  it('passes for the stage resource itself when the catch-all settings are encrypted', () => {
    const settings = catchAllSettings(true);
    expect(runControl(stage, [stage, settings])).toBeNull();
  });

  // Opposite outcome: identical catch-all block, encryption present but disabled -> finding.
  it('flags when the catch-all method settings enable caching with cache_data_encrypted false', () => {
    const settings = catchAllSettings(false);
    const result = runControl(settings, [stage, settings]);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('aws_api_gateway_method_settings.all');
    expect(result?.resourceType).toBe('aws_api_gateway_method_settings');
  });
});
