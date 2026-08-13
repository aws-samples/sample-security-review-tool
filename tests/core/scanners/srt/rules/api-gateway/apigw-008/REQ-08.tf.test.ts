import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw008TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: { stage_name: 'prod', cache_cluster_enabled: true, cache_cluster_size: '0.5' },
} as unknown as TerraformResource;

function methodSettings(name: string, settings: unknown[]): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name,
    address: `aws_api_gateway_method_settings.${name}`,
    values: {
      // reference form: user wrote aws_api_gateway_stage.prod.stage_name in HCL
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: 'aws_api_gateway_stage.prod',
      method_path: `${name}/GET`,
      settings,
    },
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 (Terraform) - mixed method settings where every caching-enabled method encrypts cache data', () => {
  // Primary behavior owned by APIGW-008: only methods with caching enabled need encrypted cache data.
  it('passes when all caching-enabled method settings encrypt cache data and other settings only tune non-caching behavior', () => {
    const cachedItems = methodSettings('items', [
      { caching_enabled: true, cache_data_encrypted: true, cache_ttl_in_seconds: 300 },
    ]);
    const cachedItem = methodSettings('item', [
      { caching_enabled: true, cache_data_encrypted: true },
    ]);
    const throttleOnly = methodSettings('create', [
      { caching_enabled: false, throttling_burst_limit: 100, throttling_rate_limit: 50 },
    ]);
    const loggingOnly = methodSettings('all', [
      { logging_level: 'INFO', metrics_enabled: true, caching_enabled: false },
    ]);
    const all = [stage, cachedItems, cachedItem, throttleOnly, loggingOnly];

    for (const resource of [cachedItems, cachedItem, throttleOnly, loggingOnly]) {
      expect(run(resource, all)).toBeNull();
    }
  });

  it('flags the method settings when one caching-enabled method leaves cache data unencrypted (opposite case)', () => {
    const cachedItems = methodSettings('items', [
      { caching_enabled: true, cache_data_encrypted: true, cache_ttl_in_seconds: 300 },
    ]);
    const unencrypted = methodSettings('item', [
      { caching_enabled: true, cache_data_encrypted: false },
    ]);
    const throttleOnly = methodSettings('create', [
      { caching_enabled: false, throttling_burst_limit: 100, throttling_rate_limit: 50 },
    ]);
    const all = [stage, cachedItems, unencrypted, throttleOnly];

    expect(run(cachedItems, all)).toBeNull();
    expect(run(throttleOnly, all)).toBeNull();

    const result = run(unencrypted, all);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
  });
});
