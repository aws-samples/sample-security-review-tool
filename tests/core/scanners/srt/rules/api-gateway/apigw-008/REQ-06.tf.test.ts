import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (APIGW-008): Caching enabled for one specific method/path while cache data
 * encryption is disabled or unspecified for that method => FLAG.
 */

const factory = new Apigw008TfAdapterFactory();

const stageResource: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    stage_name: 'prod',
    rest_api_id: 'aws_api_gateway_rest_api.api',
    cache_cluster_enabled: true,
    cache_cluster_size: '0.5',
  },
} as unknown as TerraformResource;

function methodSettings(settings: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'pets_get',
    address: 'aws_api_gateway_method_settings.pets_get',
    values: {
      // reference form: wired to the stage/api by resource address
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: 'aws_api_gateway_stage.prod',
      method_path: 'pets/GET',
      settings: [settings],
    },
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [stageResource, resource],
  };
  const adapter = factory.bind(context) as Apigw008Adapter;
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 REQ-06 (Terraform): per-method caching without cache data encryption', () => {
  it('flags method settings where the single cached method sets cache_data_encrypted false', () => {
    const result = run(methodSettings({ caching_enabled: true, cache_data_encrypted: false }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceType).toBe('aws_api_gateway_method_settings');
    expect(result?.resourceName).toBe('aws_api_gateway_method_settings.pets_get');
  });

  it('flags method settings where the single cached method omits cache_data_encrypted', () => {
    const result = run(methodSettings({ caching_enabled: true }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
  });

  // Opposite outcome: nearest input that flips the verdict — the same single
  // cached method path, but with cache data encryption enabled.
  it('does not flag when the same cached method sets cache_data_encrypted true', () => {
    const result = run(methodSettings({ caching_enabled: true, cache_data_encrypted: true }));

    expect(result).toBeNull();
  });
});
