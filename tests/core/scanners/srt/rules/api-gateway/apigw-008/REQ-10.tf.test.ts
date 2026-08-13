import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (APIGW-008): a per-method aws_api_gateway_method_settings block that
 * overrides the catch-all's cache_data_encrypted to false while keeping
 * caching_enabled true must be flagged.
 */

const factory = new Apigw008TfAdapterFactory();

const stage: TerraformResource = {
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

// Reference form — HCL wired stage_name = aws_api_gateway_stage.prod.stage_name
const catchAllSettings: TerraformResource = {
  type: 'aws_api_gateway_method_settings',
  name: 'all',
  address: 'aws_api_gateway_method_settings.all',
  values: {
    rest_api_id: 'aws_api_gateway_rest_api.api',
    stage_name: 'aws_api_gateway_stage.prod',
    method_path: '*/*',
    settings: [{ caching_enabled: true, cache_data_encrypted: true }],
  },
} as unknown as TerraformResource;

function methodOverride(cacheDataEncrypted: unknown): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'pets_get',
    address: 'aws_api_gateway_method_settings.pets_get',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: 'aws_api_gateway_stage.prod',
      method_path: 'pets/GET',
      settings: [{ caching_enabled: true, cache_data_encrypted: cacheDataEncrypted }],
    },
  } as unknown as TerraformResource;
}

function scan(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  return apigw008Control.run(factory.bind(context) as Apigw008Adapter, context);
}

describe('APIGW-008 REQ-10 (Terraform): per-method override of catch-all encryption', () => {
  it('flags the method setting that keeps caching enabled but disables cache data encryption', () => {
    const override = methodOverride(false);
    const all = [stage, catchAllSettings, override];

    const result = scan(override, all);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('aws_api_gateway_method_settings.pets_get');
    expect(result?.resourceType).toBe('aws_api_gateway_method_settings');
  });

  // Opposite outcome: nearest input that flips the verdict — the specific
  // method setting keeps encryption enabled like the catch-all does.
  it('does not flag when the specific method setting keeps cache data encryption enabled', () => {
    const override = methodOverride(true);
    const all = [stage, catchAllSettings, override];

    expect(scan(override, all)).toBeNull();
  });

  it('does not flag the compliant catch-all setting itself', () => {
    const all = [stage, catchAllSettings, methodOverride(false)];

    expect(scan(catchAllSettings, all)).toBeNull();
  });
});
