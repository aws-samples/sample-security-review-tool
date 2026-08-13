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
  values: {
    stage_name: 'prod',
    rest_api_id: 'aws_api_gateway_rest_api.api',
    deployment_id: 'aws_api_gateway_deployment.dep',
  },
} as unknown as TerraformResource;

// Reference form: stage_name = aws_api_gateway_stage.prod.stage_name in HCL,
// collapsed by the plan reader to the stage's address.
function referenceMethodSettings(loggingLevel: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'all',
    address: 'aws_api_gateway_method_settings.all',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: 'aws_api_gateway_stage.prod',
      method_path: '*/*',
      settings: [{ logging_level: loggingLevel, metrics_enabled: true }],
    },
  } as unknown as TerraformResource;
}

// Literal form: stage_name = "prod" in HCL.
function literalMethodSettings(loggingLevel: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'all',
    address: 'aws_api_gateway_method_settings.all',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: 'prod',
      method_path: '*/*',
      settings: [{ logging_level: loggingLevel, metrics_enabled: true }],
    },
  } as unknown as TerraformResource;
}

function run(methodSettings: TerraformResource) {
  const allResources = [stage, methodSettings];
  const context: TfContext = { projectName: 'test-project', resource: stage, allResources };
  const adapter = factory.bind(context) as Apigw006Adapter;
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 (Terraform) - catch-all method setting with logging level off', () => {
  // Primary behavior owned by this requirement: a catch-all method setting whose
  // logging level is explicitly OFF means no execution logs reach CloudWatch Logs.
  it('flags a stage whose catch-all method settings (reference form) set logging_level to OFF', () => {
    const result = run(referenceMethodSettings('OFF'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });

  it('flags a stage whose catch-all method settings (literal form) set logging_level to OFF', () => {
    const result = run(literalMethodSettings('OFF'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });

  // Opposite outcome: nearest input that flips the verdict - same catch-all
  // method settings, but with an accepted logging level in effect.
  it('does not flag an otherwise identical catch-all method settings block with logging_level ERROR', () => {
    expect(run(referenceMethodSettings('ERROR'))).toBeNull();
  });
});
