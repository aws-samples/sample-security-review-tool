import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.tf.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw006TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: { stage_name: 'prod', rest_api_id: 'aws_api_gateway_rest_api.api' },
} as unknown as TerraformResource;

function methodSettings(
  name: string,
  stageName: string,
  methodPath: string,
  loggingLevel: string,
): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name,
    address: `aws_api_gateway_method_settings.${name}`,
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: stageName,
      method_path: methodPath,
      settings: [{ logging_level: loggingLevel, metrics_enabled: true }],
    },
  } as unknown as TerraformResource;
}

function scan(others: TerraformResource[]) {
  const allResources = [stage, ...others];
  const context: TfContext = { projectName: 'test-project', resource: stage, allResources };
  const adapter = factory.bind(context) as Apigw006Adapter;
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 (Terraform) - method setting that turns logging off for one method', () => {
  // Primary behavior owned by this requirement: a narrower aws_api_gateway_method_settings
  // with logging_level = "OFF" leaves that method unlogged, so the stage is non-compliant
  // even though a catch-all method_path "*/*" enables logging.
  it('flags a stage when a specific method_path setting sets logging_level OFF (reference form)', () => {
    const result = scan([
      methodSettings('all', 'aws_api_gateway_stage.prod', '*/*', 'INFO'),
      methodSettings('orders', 'aws_api_gateway_stage.prod', 'orders/GET', 'OFF'),
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
  });

  it('flags a stage when a specific method_path setting sets logging_level OFF (literal stage name form)', () => {
    const result = scan([
      methodSettings('all', 'prod', '*/*', 'INFO'),
      methodSettings('orders', 'prod', 'orders/GET', 'OFF'),
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });

  // Opposite outcome: identical shape, only the narrower setting's logging_level
  // changes from OFF to an accepted level, so every method remains logged.
  it('does not flag when the narrower method setting uses an accepted logging level instead of OFF', () => {
    const result = scan([
      methodSettings('all', 'aws_api_gateway_stage.prod', '*/*', 'INFO'),
      methodSettings('orders', 'aws_api_gateway_stage.prod', 'orders/GET', 'INFO'),
    ]);

    expect(result).toBeNull();
  });
});
