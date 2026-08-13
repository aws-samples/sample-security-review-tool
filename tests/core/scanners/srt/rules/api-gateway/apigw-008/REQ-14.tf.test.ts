import { describe, it, expect } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-14 (Terraform) — APIGW-008
 * Requirement under test: when whether caching is enabled cannot be resolved at
 * plan time (caching_enabled is null / unknown) and no cache data encryption is
 * configured, the control must NOT report a finding.
 *
 * The opposite-outcome test belongs to the primary APIGW-008 behavior.
 */

const factory = new Apigw008TfAdapterFactory();

function run(resource: TerraformResource, allResources: TerraformResource[] = [resource]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  return apigw008Control.run(factory.bind(context) as never, context);
}

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: { stage_name: 'prod', rest_api_id: 'aws_api_gateway_rest_api.api', cache_cluster_enabled: true },
} as unknown as TerraformResource;

describe('APIGW-008 REQ-14 (Terraform): unresolvable caching state, no cache encryption', () => {
  it('does not report a finding when caching_enabled is unknown at plan time and cache_data_encrypted is absent', () => {
    const methodSettings: TerraformResource = {
      type: 'aws_api_gateway_method_settings',
      name: 'all',
      address: 'aws_api_gateway_method_settings.all',
      values: {
        // reference form — wired to the stage via aws_api_gateway_stage.prod.stage_name
        rest_api_id: 'aws_api_gateway_rest_api.api',
        stage_name: 'aws_api_gateway_stage.prod',
        method_path: '*/*',
        settings: [
          {
            caching_enabled: null,
          },
        ],
      },
    } as unknown as TerraformResource;

    expect(run(methodSettings, [stage, methodSettings])).toBeNull();
  });

  // Opposite outcome — primary APIGW-008 behavior: caching is KNOWN enabled and
  // cache data encryption is explicitly disabled, so a finding must be reported.
  it('reports a finding when caching_enabled is true and cache_data_encrypted is false', () => {
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
          },
        ],
      },
    } as unknown as TerraformResource;

    const result = run(methodSettings, [stage, methodSettings]);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
  });
});
