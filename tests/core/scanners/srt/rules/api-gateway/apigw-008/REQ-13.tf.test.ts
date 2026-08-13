import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const PROJECT_NAME = 'test-project';

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

/**
 * Reference form: stage_name = aws_api_gateway_stage.prod.stage_name in HCL is
 * collapsed by the plan reader to the stage's address.
 */
function methodSettings(cacheDataEncrypted: unknown): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'all',
    address: 'aws_api_gateway_method_settings.all',
    values: {
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

function scan(resource: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: PROJECT_NAME,
    resource,
    allResources: [stage, resource],
  };
  const adapter = factory.bind(context) as Apigw008Adapter;
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 (Terraform) - indeterminate cache data encryption value', () => {
  // Primary behavior owned by this requirement: caching is on, but the
  // encryption value is unknown at plan time (recorded as null) -> must pass.
  it('passes when cache_data_encrypted is unknown at plan time (null)', () => {
    const result = scan(methodSettings(null));

    expect(result).toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict - the value is
  // known and is "not encrypted".
  it('flags the method settings when cache_data_encrypted is known to be false (owned by the unencrypted-cache requirement)', () => {
    const result = scan(methodSettings(false));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('aws_api_gateway_method_settings.all');
    expect(result?.resourceType).toBe('aws_api_gateway_method_settings');
  });
});
