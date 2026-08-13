import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.tf.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw006TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    stage_name: 'prod',
    rest_api_id: 'aws_api_gateway_rest_api.api',
  },
} as unknown as TerraformResource;

function methodSettings(stageName: string, methodPath: string, loggingLevel: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'all',
    address: 'aws_api_gateway_method_settings.all',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: stageName,
      method_path: methodPath,
      settings: [{ logging_level: loggingLevel }],
    },
  } as unknown as TerraformResource;
}

function assess(allResources: TerraformResource[]): ScanResult | null {
  const ctx: TfContext = {
    projectName: 'test-project',
    resource: stage,
    allResources,
  };
  const adapter = factory.bind(ctx) as unknown as Apigw006Adapter;
  return apigw006Control.run(adapter, ctx);
}

describe('APIGW-006 (Terraform) — catch-all method settings supplied by a separate resource', () => {
  // Primary behavior owned by this requirement: coverage provided by a related
  // aws_api_gateway_method_settings resource that targets the assessed stage.
  it('passes when a separate method settings resource references the stage (reference form) with a catch-all INFO level', () => {
    const result = assess([stage, methodSettings('aws_api_gateway_stage.prod', '*/*', 'INFO')]);

    expect(result).toBeNull();
  });

  it('passes when the separate method settings resource wires the stage by literal name with a catch-all ERROR level', () => {
    const result = assess([stage, methodSettings('prod', '*/*', 'ERROR')]);

    expect(result).toBeNull();
  });

  // Opposite outcome: the same catch-all setting targeting the same stage, but
  // with a logging level that is not an accepted execution logging level.
  it('flags the stage when the referencing catch-all method settings use a non-accepted logging level', () => {
    const result = assess([stage, methodSettings('aws_api_gateway_stage.prod', '*/*', 'OFF')]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });

  // Opposite outcome: an equivalent catch-all setting that targets a different stage
  // therefore provides no coverage for the assessed stage.
  it('flags the stage when the catch-all method settings reference a different stage', () => {
    const result = assess([stage, methodSettings('aws_api_gateway_stage.other', '*/*', 'INFO')]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });
});
