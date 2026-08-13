import { describe, expect, it } from 'vitest';

import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw008TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: { stage_name: 'prod', cache_cluster_enabled: true },
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
      // reference form: stage_name = aws_api_gateway_stage.prod.stage_name
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: 'aws_api_gateway_stage.prod',
      method_path: methodPath,
      settings: [settings],
    },
  } as unknown as TerraformResource;
}

const catchAllNoCaching = methodSettings('all', '*/*', { caching_enabled: false });

function scan(resource: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 (Terraform) - catch-all leaves caching off while a specific method caches with encryption', () => {
  // Primary behavior owned by APIGW-008: only cached methods must encrypt cache data.
  it('passes for the specific cached method when it enables cache data encryption', () => {
    const specific = methodSettings('items_get', 'items/GET', {
      caching_enabled: true,
      cache_data_encrypted: true,
    });
    const all = [stage, catchAllNoCaching, specific];

    expect(scan(specific, all)).toBeNull();
    expect(scan(catchAllNoCaching, all)).toBeNull();
    expect(scan(stage, all)).toBeNull();
  });

  it('flags the specific cached method when it leaves cache data encryption disabled', () => {
    const specific = methodSettings('items_get', 'items/GET', {
      caching_enabled: true,
      cache_data_encrypted: false,
    });
    const all = [stage, catchAllNoCaching, specific];

    const result = scan(specific, all);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('aws_api_gateway_method_settings.items_get');
  });
});
