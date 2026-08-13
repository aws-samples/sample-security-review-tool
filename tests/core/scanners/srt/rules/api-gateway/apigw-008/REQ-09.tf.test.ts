import { describe, it, expect } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { TfContext, TerraformResource, ScanResult } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (APIGW-008): API Gateway stages with caching enabled must have cache data
 * encryption enabled for ALL cached methods.
 *
 * Scenario: multiple method-level settings enable caching, some encrypted and at
 * least one not encrypted -> expected behavior: FLAG.
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

function methodSettings(name: string, settings: unknown[]): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name,
    address: `aws_api_gateway_method_settings.${name}`,
    values: {
      // Reference form: stage_name wired via aws_api_gateway_stage.prod.stage_name
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: 'aws_api_gateway_stage.prod',
      settings,
    },
  } as unknown as TerraformResource;
}

function scan(resource: TerraformResource, all: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: all,
  };
  const adapter = factory.bind(context) as Apigw008Adapter;
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 REQ-09 (Terraform): per-method cache encryption must cover every cached method', () => {
  it('flags method settings where several methods enable caching but one lacks cache_data_encrypted', () => {
    const resource = methodSettings('all', [
      { method_path: 'items/GET', caching_enabled: true, cache_data_encrypted: true },
      { method_path: 'items/POST', caching_enabled: true, cache_data_encrypted: true },
      { method_path: 'orders/GET', caching_enabled: true, cache_data_encrypted: false },
    ]);

    const result = scan(resource, [stage, resource]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceType).toBe('aws_api_gateway_method_settings');
    expect(result?.resourceName).toBe('aws_api_gateway_method_settings.all');
  });

  // Nearest input that flips the verdict: the same cached methods, with the single
  // offending method's cache_data_encrypted set to true instead of false.
  it('does not flag when every cached method sets cache_data_encrypted to true', () => {
    const resource = methodSettings('all', [
      { method_path: 'items/GET', caching_enabled: true, cache_data_encrypted: true },
      { method_path: 'items/POST', caching_enabled: true, cache_data_encrypted: true },
      { method_path: 'orders/GET', caching_enabled: true, cache_data_encrypted: true },
    ]);

    const result = scan(resource, [stage, resource]);

    expect(result).toBeNull();
  });
});
