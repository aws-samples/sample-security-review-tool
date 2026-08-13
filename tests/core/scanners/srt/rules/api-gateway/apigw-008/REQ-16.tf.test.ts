import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-16 (APIGW-008): Cache-data-encryption coverage must apply to the ASSESSED stage.
 * A method-settings resource that enables cache_data_encrypted for a DIFFERENT stage
 * does not cover the assessed stage -> flag.
 */

const factory = new Apigw008TfAdapterFactory();

const prodStage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: { stage_name: 'prod', cache_cluster_enabled: true },
} as unknown as TerraformResource;

function methodSettings(options: {
  readonly name: string;
  readonly stageName: string;
  readonly encrypted: boolean;
}): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: options.name,
    address: `aws_api_gateway_method_settings.${options.name}`,
    values: {
      stage_name: options.stageName,
      method_path: '*/*',
      settings: [{ caching_enabled: true, cache_data_encrypted: options.encrypted }],
    },
  } as unknown as TerraformResource;
}

function assessProdStage(allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: prodStage,
    allResources,
  };
  return apigw008Control.run(factory.bind(context), context);
}

describe('APIGW-008 REQ-16 (Terraform): encryption must cover the assessed stage', () => {
  it('flags the assessed stage (reference form) when only another stage has cache data encryption enabled', () => {
    const result = assessProdStage([
      prodStage,
      // Targets the assessed stage by reference — caching on, encryption off.
      methodSettings({ name: 'prod', stageName: 'aws_api_gateway_stage.prod', encrypted: false }),
      // Encryption enabled, but for a different stage.
      methodSettings({ name: 'dev', stageName: 'aws_api_gateway_stage.dev', encrypted: true }),
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
  });

  it('flags the assessed stage (literal form) when only another stage has cache data encryption enabled', () => {
    const result = assessProdStage([
      prodStage,
      methodSettings({ name: 'prod', stageName: 'prod', encrypted: false }),
      methodSettings({ name: 'dev', stageName: 'dev', encrypted: true }),
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
  });

  // Opposite outcome: encryption is configured for the assessed stage and the
  // unencrypted configuration targets the other stage -> no finding.
  it('does not flag the assessed stage when its own method settings are encrypted and only another stage is unencrypted', () => {
    const result = assessProdStage([
      prodStage,
      methodSettings({ name: 'prod', stageName: 'aws_api_gateway_stage.prod', encrypted: true }),
      methodSettings({ name: 'dev', stageName: 'aws_api_gateway_stage.dev', encrypted: false }),
    ]);

    expect(result).toBeNull();
  });
});
