import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw008TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    stage_name: 'prod',
    cache_cluster_enabled: true,
  },
} as unknown as TerraformResource;

function methodSettings(settings: unknown): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'all',
    address: 'aws_api_gateway_method_settings.all',
    values: {
      // reference form - user wrote aws_api_gateway_stage.prod.stage_name in HCL
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: 'aws_api_gateway_stage.prod',
      settings,
    },
  } as unknown as TerraformResource;
}

function runControl(resource: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [stage, resource],
  };
  const adapter = factory.bind(context) as Apigw008Adapter;
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 (Terraform) - method settings collection present but empty', () => {
  // Primary behavior owned by this requirement: a settings collection with no
  // entries means no method has caching enabled, so the rule does not apply.
  it('passes when the settings collection is present but has no entries', () => {
    expect(runControl(methodSettings([]))).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict - the collection
  // contains a cached method whose cache data is not encrypted.
  it('flags when the settings collection contains a caching-enabled entry without cache data encryption', () => {
    const result = runControl(
      methodSettings([{ caching_enabled: true, cache_data_encrypted: false }]),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('aws_api_gateway_method_settings.all');
  });
});
