import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw008TfAdapterFactory();

/**
 * Runs APIGW-008 over every applicable resource in the plan and
 * returns the findings that were produced.
 */
function scan(allResources: TerraformResource[]): ScanResult[] {
  const results: ScanResult[] = [];
  for (const resource of allResources) {
    if (!factory.appliesTo(resource.type)) continue;
    const context: TfContext = { projectName: 'test-project', resource, allResources };
    const adapter = factory.bind(context) as Apigw008Adapter;
    const result = apigw008Control.run(adapter, context);
    if (result) results.push(result);
  }
  return results;
}

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    rest_api_id: 'aws_api_gateway_rest_api.api',
    stage_name: 'prod',
    deployment_id: 'aws_api_gateway_deployment.dep',
  },
} as unknown as TerraformResource;

describe('APIGW-008 (Terraform) - stage without any method settings', () => {
  // Primary behavior owned by this requirement: no caching anywhere => nothing to encrypt => pass.
  it('passes a stage with no aws_api_gateway_method_settings resource at all', () => {
    expect(scan([stage])).toEqual([]);
  });

  it('passes a stage whose method settings exist (reference form) but leave caching disabled', () => {
    const methodSettings: TerraformResource = {
      type: 'aws_api_gateway_method_settings',
      name: 'all',
      address: 'aws_api_gateway_method_settings.all',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        stage_name: 'aws_api_gateway_stage.prod',
        method_path: '*/*',
        settings: [
          {
            caching_enabled: false,
            logging_level: 'INFO',
          },
        ],
      },
    } as unknown as TerraformResource;

    expect(scan([stage, methodSettings])).toEqual([]);
  });

  // Opposite outcome: caching IS enabled and the cached data is unencrypted => finding.
  it('flags a stage whose method settings enable caching without cache data encryption', () => {
    const methodSettings: TerraformResource = {
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
            cache_data_encrypted: false,
            logging_level: 'INFO',
          },
        ],
      },
    } as unknown as TerraformResource;

    const results = scan([stage, methodSettings]);
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results.every(r => r.check_id === 'APIGW-008')).toBe(true);
  });
});
