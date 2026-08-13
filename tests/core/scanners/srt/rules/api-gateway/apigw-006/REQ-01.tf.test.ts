import { describe, it, expect } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * APIGW-006 — API Gateway stages must have CloudWatch execution logging enabled,
 * with the logging level set to INFO or ERROR for all methods (or via a catch-all
 * method setting).
 *
 * REQ-01 (primary behavior owned by this file): a stage with NO method-level
 * logging configuration at all (no aws_api_gateway_method_settings covering it)
 * must be flagged.
 */

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

function runControl(allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: stage,
    allResources,
  };
  const adapter = new Apigw006TfAdapterFactory().bind(context);
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 REQ-01 (Terraform): stage with no method-level logging configuration', () => {
  it('flags a stage when the plan contains no aws_api_gateway_method_settings resource', () => {
    const result = runControl([stage]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });

  it('flags a stage when method settings exist but target a different stage', () => {
    const otherStageSettings: TerraformResource = {
      type: 'aws_api_gateway_method_settings',
      name: 'other',
      address: 'aws_api_gateway_method_settings.other',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        stage_name: 'aws_api_gateway_stage.dev',
        method_path: '*/*',
        settings: [{ logging_level: 'INFO' }],
      },
    } as unknown as TerraformResource;

    const result = runControl([stage, otherStageSettings]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });

  // Opposite outcome: the nearest input that flips the verdict — the same stage,
  // now covered by a catch-all method settings block enabling ERROR logging.
  // Reference form: stage_name written in HCL as aws_api_gateway_stage.prod.stage_name.
  it('does not flag a stage covered by a catch-all method settings block (reference form)', () => {
    const settings: TerraformResource = {
      type: 'aws_api_gateway_method_settings',
      name: 'all',
      address: 'aws_api_gateway_method_settings.all',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        stage_name: 'aws_api_gateway_stage.prod',
        method_path: '*/*',
        settings: [{ logging_level: 'ERROR' }],
      },
    } as unknown as TerraformResource;

    const result = runControl([stage, settings]);

    expect(result).toBeNull();
  });

  // Literal form: stage_name written in HCL as the literal stage name string.
  it('does not flag a stage covered by a catch-all method settings block (literal form)', () => {
    const settings: TerraformResource = {
      type: 'aws_api_gateway_method_settings',
      name: 'all',
      address: 'aws_api_gateway_method_settings.all',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        stage_name: 'prod',
        method_path: '*/*',
        settings: [{ logging_level: 'INFO' }],
      },
    } as unknown as TerraformResource;

    const result = runControl([stage, settings]);

    expect(result).toBeNull();
  });
});
