import { describe, it, expect } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import { Apigw006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw006TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: { stage_name: 'prod', rest_api_id: 'aws_api_gateway_rest_api.api' },
} as unknown as TerraformResource;

function methodSettings(methodPath: string, loggingLevel: string, stageName: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'logging',
    address: 'aws_api_gateway_method_settings.logging',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: stageName,
      method_path: methodPath,
      settings: [{ logging_level: loggingLevel }],
    },
  } as unknown as TerraformResource;
}

function run(...resources: TerraformResource[]) {
  const allResources = [stage, ...resources];
  const context: TfContext = { projectName: 'test-project', resource: stage, allResources };
  const adapter = factory.bind(context) as Apigw006Adapter;
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 (Terraform) — execution logging coverage for all methods', () => {
  // Primary behavior owned by this requirement: method_settings scoped to one
  // specific method/path leaves other methods without execution logging => flag.
  it('flags a stage whose only method_settings targets one specific method and path (reference form)', () => {
    const result = run(methodSettings('orders/GET', 'INFO', 'aws_api_gateway_stage.prod'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });

  it('flags a stage whose only method_settings targets one specific method and path (literal stage name)', () => {
    const result = run(methodSettings('orders/POST', 'ERROR', 'prod'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });

  // Opposite outcome: same shape, but method_path is the catch-all "*/*" covering
  // every method and path, so coverage is complete => no finding.
  it('does not flag a stage whose method_settings uses the catch-all method_path', () => {
    const result = run(methodSettings('*/*', 'INFO', 'aws_api_gateway_stage.prod'));

    expect(result).toBeNull();
  });
});
