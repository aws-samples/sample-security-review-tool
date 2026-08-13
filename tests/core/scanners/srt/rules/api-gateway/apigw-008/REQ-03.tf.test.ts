import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-03 (Terraform) — APIGW-008
 * An aws_api_gateway_method_settings block applying to every method
 * (method_path "*​/*") enables caching but omits cache_data_encrypted.
 * Cache data encryption defaults to disabled, so the control must flag.
 */

const factory = new Apigw008TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: { stage_name: 'prod', cache_cluster_enabled: true },
} as unknown as TerraformResource;

function methodSettings(settings: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'all',
    address: 'aws_api_gateway_method_settings.all',
    values: {
      // reference form: stage_name = aws_api_gateway_stage.prod.stage_name
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: 'aws_api_gateway_stage.prod',
      method_path: '*/*',
      settings: [settings],
    },
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [stage, resource],
  };
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 REQ-03 (Terraform): catch-all caching without cache data encryption', () => {
  it('flags catch-all method settings that enable caching and omit cache_data_encrypted', () => {
    const result = run(methodSettings({ caching_enabled: true }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceType).toBe('aws_api_gateway_method_settings');
    expect(result?.resourceName).toBe('aws_api_gateway_method_settings.all');
  });

  // Opposite outcome: identical catch-all block with encryption explicitly enabled.
  // Primary behavior (flagging the omitted value) is owned by the test above.
  it('does not flag when the same catch-all block sets cache_data_encrypted to true', () => {
    const result = run(methodSettings({ caching_enabled: true, cache_data_encrypted: true }));

    expect(result).toBeNull();
  });
});
