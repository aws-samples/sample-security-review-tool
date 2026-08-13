import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import { Apigw006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (APIGW-006): A stage covered by a catch-all aws_api_gateway_method_settings
 * with an accepted logging_level PASSES even when additional method settings configure
 * unrelated features (metrics, throttling) without setting a logging level.
 */

const factory = new Apigw006TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'this',
  address: 'aws_api_gateway_stage.this',
  values: { stage_name: 'prod', rest_api_id: 'aws_api_gateway_rest_api.this' },
} as unknown as TerraformResource;

function methodSettings(name: string, stageName: string, methodPath: string, settings: Record<string, unknown>[]): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name,
    address: `aws_api_gateway_method_settings.${name}`,
    values: { stage_name: stageName, method_path: methodPath, settings },
  } as unknown as TerraformResource;
}

function run(others: TerraformResource[]) {
  const allResources = [stage, ...others];
  const context: TfContext = { projectName: 'test-project', resource: stage, allResources };
  const adapter = factory.bind(context) as Apigw006Adapter;
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 REQ-09 (Terraform)', () => {
  it('passes with a reference-form catch-all setting at INFO plus a metrics-only setting for one method', () => {
    const result = run([
      methodSettings('all', 'aws_api_gateway_stage.this', '*/*', [{ logging_level: 'INFO' }]),
      methodSettings('metrics', 'aws_api_gateway_stage.this', 'items/GET', [{ metrics_enabled: true }]),
    ]);

    expect(result).toBeNull();
  });

  it('passes with a literal-form catch-all setting at ERROR plus a throttling-only setting for one method', () => {
    const result = run([
      methodSettings('all', 'prod', '*/*', [{ logging_level: 'ERROR' }]),
      methodSettings('throttle', 'prod', 'items/POST', [{ throttling_burst_limit: 100, throttling_rate_limit: 50 }]),
    ]);

    expect(result).toBeNull();
  });

  it('passes when an additional catch-all setting configures only metrics alongside the logging catch-all', () => {
    const result = run([
      methodSettings('all', 'aws_api_gateway_stage.this', '*/*', [{ logging_level: 'INFO' }]),
      methodSettings('metrics', 'aws_api_gateway_stage.this', '*/*', [{ metrics_enabled: true }]),
    ]);

    expect(result).toBeNull();
  });

  // Opposite outcome: same shape, but the catch-all logging level is not accepted.
  // Primary behavior for an unaccepted level belongs to the logging-level requirement.
  it('flags when the catch-all setting uses a non-accepted logging level alongside the unrelated setting', () => {
    const result = run([
      methodSettings('all', 'aws_api_gateway_stage.this', '*/*', [{ logging_level: 'OFF' }]),
      methodSettings('metrics', 'aws_api_gateway_stage.this', 'items/GET', [{ metrics_enabled: true }]),
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });
});
