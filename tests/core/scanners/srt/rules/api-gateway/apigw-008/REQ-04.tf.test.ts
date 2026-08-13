import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw008TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    stage_name: 'prod',
    rest_api_id: 'aws_api_gateway_rest_api.api',
    cache_cluster_enabled: true,
  },
} as unknown as TerraformResource;

function buildMethodSettings(cacheDataEncrypted: unknown): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'all',
    address: 'aws_api_gateway_method_settings.all',
    values: {
      // Reference form: user wrote aws_api_gateway_stage.prod.stage_name in HCL
      rest_api_id: 'aws_api_gateway_rest_api.api',
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

function scan(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [stage, resource],
  };
  const adapter = factory.bind(context) as Apigw008Adapter;
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 REQ-04 (Terraform): catch-all method settings with caching enabled and cache data encryption explicitly disabled', () => {
  // Primary behavior owned by this requirement: flag the unencrypted cached catch-all setting.
  it('flags catch-all method settings that enable caching and explicitly disable cache data encryption', () => {
    const result = scan(buildMethodSettings(false));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceType).toBe('aws_api_gateway_method_settings');
    expect(result?.resourceName).toBe('aws_api_gateway_method_settings.all');
  });

  // Opposite outcome: same catch-all settings, encryption present and enabled -> no finding.
  it('does not flag catch-all method settings that enable caching with cache data encryption enabled', () => {
    const result = scan(buildMethodSettings(true));

    expect(result).toBeNull();
  });
});
