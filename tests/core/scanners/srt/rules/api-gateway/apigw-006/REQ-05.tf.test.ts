import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.tf.js';
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

// Reference form: stage_name written as aws_api_gateway_stage.prod.stage_name in HCL,
// collapsed by the plan reader to the stage address.
function methodSettingsReferencingStage(loggingLevel: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'all',
    address: 'aws_api_gateway_method_settings.all',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: 'aws_api_gateway_stage.prod',
      method_path: '*/*',
      settings: [{ logging_level: loggingLevel }],
    },
  } as unknown as TerraformResource;
}

// Literal form: stage_name written as the literal stage name string in HCL.
function methodSettingsLiteralStage(loggingLevel: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'all',
    address: 'aws_api_gateway_method_settings.all',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: 'prod',
      method_path: '*/*',
      settings: [{ logging_level: loggingLevel }],
    },
  } as unknown as TerraformResource;
}

function runStage(methodSettings: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: stage,
    allResources: [stage, methodSettings],
  };
  const adapter = factory.bind(context);
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 (Terraform) — catch-all method settings logging level must be INFO or ERROR', () => {
  // Primary behavior owned by this requirement: an unrecognized logging level must be flagged.
  it('flags a stage whose catch-all method settings use an unrecognized logging level (reference form)', () => {
    const result = runStage(methodSettingsReferencingStage('VERBOSE'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });

  it('flags a stage whose catch-all method settings use an unrecognized logging level (literal form)', () => {
    const result = runStage(methodSettingsLiteralStage('DEBUG'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });

  // Opposite outcome: identical catch-all settings, but with an accepted level present.
  it('does not flag a stage whose catch-all method settings use the accepted ERROR logging level', () => {
    expect(runStage(methodSettingsReferencingStage('ERROR'))).toBeNull();
  });
});
