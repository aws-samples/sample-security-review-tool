import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (APIGW-006): A stage whose method settings collection contains no entries
 * configures no logging level for any method and must be flagged.
 */

const factory = new Apigw006TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'api',
  address: 'aws_api_gateway_stage.api',
  values: { stage_name: 'prod', rest_api_id: 'aws_api_gateway_rest_api.api' },
} as unknown as TerraformResource;

function methodSettings(settings: unknown, stageName: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'api',
    address: 'aws_api_gateway_method_settings.api',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: stageName,
      method_path: '*/*',
      settings,
    },
  } as unknown as TerraformResource;
}

function scan(allResources: TerraformResource[]): ReturnType<typeof apigw006Control.run> {
  const context: TfContext = {
    projectName: 'test-project',
    resource: stage,
    allResources,
  };
  const adapter = factory.bind(context);
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 Terraform - empty method settings collection', () => {
  it('flags a stage whose method settings block list is empty (reference form)', () => {
    const result = scan([stage, methodSettings([], 'aws_api_gateway_stage.api')]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.api');
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
  });

  it('flags a stage whose method settings block list is empty (literal stage name form)', () => {
    const result = scan([stage, methodSettings([], 'prod')]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });

  // Opposite outcome: the nearest input that flips the verdict is the same settings
  // collection holding one entry with an accepted logging level.
  it('does not flag a stage whose method settings block list has an entry with an accepted logging level', () => {
    const result = scan([
      stage,
      methodSettings([{ logging_level: 'INFO' }], 'aws_api_gateway_stage.api'),
    ]);

    expect(result).toBeNull();
  });
});
