import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import { Apigw006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw006TfAdapterFactory();

/**
 * REQ-08 (APIGW-006): A stage with no catch-all method setting must be flagged,
 * even when every method declared for the API has its own method_settings
 * resource with a valid logging level.
 */
const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: { stage_name: 'prod', rest_api_id: 'aws_api_gateway_rest_api.api' },
} as unknown as TerraformResource;

const getMethod: TerraformResource = {
  type: 'aws_api_gateway_method',
  name: 'get_items',
  address: 'aws_api_gateway_method.get_items',
  values: { http_method: 'GET', resource_id: 'aws_api_gateway_resource.items' },
} as unknown as TerraformResource;

const postMethod: TerraformResource = {
  type: 'aws_api_gateway_method',
  name: 'post_items',
  address: 'aws_api_gateway_method.post_items',
  values: { http_method: 'POST', resource_id: 'aws_api_gateway_resource.items' },
} as unknown as TerraformResource;

function methodSettings(name: string, methodPath: string, loggingLevel: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name,
    address: `aws_api_gateway_method_settings.${name}`,
    // reference form: stage_name = aws_api_gateway_stage.prod.stage_name
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: 'aws_api_gateway_stage.prod',
      method_path: methodPath,
      settings: [{ logging_level: loggingLevel, metrics_enabled: true }],
    },
  } as unknown as TerraformResource;
}

function contextFor(settings: TerraformResource[]): TfContext {
  return {
    projectName: 'test-project',
    resource: stage,
    allResources: [stage, getMethod, postMethod, ...settings],
  };
}

describe('APIGW-006 REQ-08 (Terraform): per-method settings do not satisfy the catch-all requirement', () => {
  it('flags a stage covered only by per-method method_settings with valid logging levels', () => {
    const ctx = contextFor([
      methodSettings('get_items', 'items/GET', 'INFO'),
      methodSettings('post_items', 'items/POST', 'ERROR'),
    ]);
    const adapter = factory.bind(ctx) as Apigw006Adapter;

    const result = apigw006Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });

  // Opposite outcome: nearest input that flips the verdict — the same wiring,
  // but coverage is expressed as a catch-all method_path of '*/*'.
  it('does not flag the same stage when a catch-all method_settings with a valid logging level is present', () => {
    const ctx = contextFor([methodSettings('all', '*/*', 'INFO')]);
    const adapter = factory.bind(ctx) as Apigw006Adapter;

    const result = apigw006Control.run(adapter, ctx);

    expect(result).toBeNull();
  });
});
