import { describe, it, expect } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { TfContext, TerraformResource, ScanResult } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

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

function methodSettings(
  name: string,
  methodPath: string,
  settings: Record<string, unknown>,
): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name,
    address: `aws_api_gateway_method_settings.${name}`,
    values: {
      // reference form -- user wrote aws_api_gateway_stage.prod.stage_name in HCL
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: stage.address,
      method_path: methodPath,
      settings: [settings],
    },
  } as unknown as TerraformResource;
}

function scan(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter as never, context);
}

describe('APIGW-008 (Terraform) - per-method encryption does not cover a different cached method', () => {
  // Primary behavior owned by APIGW-008: encryption configured for one method
  // leaves a different, actually-caching method unencrypted.
  it('flags the method settings block that enables caching without encryption', () => {
    const cachingUnencrypted = methodSettings('items_get', 'items/GET', {
      caching_enabled: true,
      cache_data_encrypted: false,
    });
    const encryptedOtherMethod = methodSettings('orders_post', 'orders/POST', {
      caching_enabled: false,
      cache_data_encrypted: true,
    });
    const all = [stage, cachingUnencrypted, encryptedOtherMethod];

    const result = scan(cachingUnencrypted, all);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceType).toBe('aws_api_gateway_method_settings');
    expect(result?.resourceName).toBe('aws_api_gateway_method_settings.items_get');

    // The encryption-only method is not itself a violation
    expect(scan(encryptedOtherMethod, all)).toBeNull();
  });

  it('flags when the caching method omits cache_data_encrypted entirely', () => {
    const cachingUnknownEncryption = methodSettings('items_get', 'items/GET', {
      caching_enabled: true,
    });
    const encryptedOtherMethod = methodSettings('orders_post', 'orders/POST', {
      caching_enabled: false,
      cache_data_encrypted: true,
    });

    expect(scan(cachingUnknownEncryption, [stage, cachingUnknownEncryption, encryptedOtherMethod])).not.toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict -- encryption moved
  // onto the method that actually caches.
  it('does not flag when the caching method has cache_data_encrypted set to true', () => {
    const cachingEncrypted = methodSettings('items_get', 'items/GET', {
      caching_enabled: true,
      cache_data_encrypted: true,
    });
    const encryptedOtherMethod = methodSettings('orders_post', 'orders/POST', {
      caching_enabled: false,
      cache_data_encrypted: true,
    });

    expect(scan(cachingEncrypted, [stage, cachingEncrypted, encryptedOtherMethod])).toBeNull();
  });
});
