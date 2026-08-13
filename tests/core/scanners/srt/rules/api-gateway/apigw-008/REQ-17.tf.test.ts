import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw008TfAdapterFactory();

/**
 * REQ-17 (APIGW-008): caching enabled at the method level with
 * cache_data_encrypted = false is itself the failure condition; the stage has
 * no cache cluster enabled / provisioned, which must not suppress the finding.
 */
const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    stage_name: 'prod',
    // Cache cluster not enabled / no size provisioned.
    cache_cluster_enabled: false,
  },
} as unknown as TerraformResource;

function methodSettings(cacheDataEncrypted: boolean): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'items',
    address: 'aws_api_gateway_method_settings.items',
    values: {
      // Reference form: stage_name = aws_api_gateway_stage.prod.stage_name
      stage_name: 'aws_api_gateway_stage.prod',
      method_path: 'items/GET',
      settings: [
        {
          caching_enabled: true,
          cache_data_encrypted: cacheDataEncrypted,
        },
      ],
    },
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context) as Apigw008Adapter;
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 REQ-17 (Terraform)', () => {
  it('flags the method settings resource with cache_data_encrypted false when no stage cache cluster is provisioned', () => {
    const settings = methodSettings(false);
    const result = run(settings, [stage, settings]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('aws_api_gateway_method_settings.items');
  });

  it('flags the stage referenced by the unencrypted method settings even though its cache cluster is disabled', () => {
    const settings = methodSettings(false);
    const result = run(stage, [stage, settings]);

    expect(result).not.toBeNull();
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });

  // Opposite outcome: nearest input that flips the verdict — encryption enabled.
  it('does not flag when cache_data_encrypted is true', () => {
    const settings = methodSettings(true);

    expect(run(settings, [stage, settings])).toBeNull();
    expect(run(stage, [stage, settings])).toBeNull();
  });
});
