import { describe, it, expect } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-15 (APIGW-008): aws_api_gateway_method_settings is a separate resource
 * that explicitly targets a stage. When it enables caching for all of the
 * stage's methods ("*\/*") and also enables cache data encryption, the assessed
 * aws_api_gateway_stage is compliant.
 */

const factory = new Apigw008TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    rest_api_id: 'aws_api_gateway_rest_api.api',
    stage_name: 'prod',
  },
} as unknown as TerraformResource;

function methodSettings(stageName: string, cacheDataEncrypted: boolean): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'all',
    address: 'aws_api_gateway_method_settings.all',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: stageName,
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

function assess(resource: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 REQ-15 (Terraform): aws_api_gateway_method_settings supplies encrypted catch-all caching for the assessed stage', () => {
  it('passes the assessed stage when a method_settings resource referencing it enables caching for all methods with encryption', () => {
    // Reference form: stage_name = aws_api_gateway_stage.prod.stage_name
    const settings = methodSettings('aws_api_gateway_stage.prod', true);
    const result = assess(stage, [stage, settings]);
    expect(result).toBeNull();
  });

  it('passes the assessed stage when the targeting method_settings uses the literal stage name and encrypts cached data', () => {
    const settings = methodSettings('prod', true);
    const result = assess(stage, [stage, settings]);
    expect(result).toBeNull();
  });

  // Opposite outcome: identical wiring, only the encryption flag flips to false.
  it('flags the assessed stage when the referencing method_settings enables caching for all methods without encryption', () => {
    const settings = methodSettings('aws_api_gateway_stage.prod', false);
    const result = assess(stage, [stage, settings]);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });
});
