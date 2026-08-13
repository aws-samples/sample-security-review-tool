import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (APIGW-006): An aws_api_gateway_method_settings resource that configures a catch-all method_path
 * with a valid logging level, but which targets a DIFFERENT stage or a DIFFERENT REST API, provides no
 * execution logging for the assessed stage — the assessed stage must be flagged.
 */

const factory = new Apigw006TfAdapterFactory();

function resource(partial: {
  type: string;
  name: string;
  values: Record<string, unknown>;
}): TerraformResource {
  return {
    type: partial.type,
    name: partial.name,
    address: `${partial.type}.${partial.name}`,
    values: partial.values,
  } as unknown as TerraformResource;
}

const assessedStage = resource({
  type: 'aws_api_gateway_stage',
  name: 'assessed',
  values: {
    stage_name: 'prod',
    rest_api_id: 'aws_api_gateway_rest_api.api',
  },
});

const otherStage = resource({
  type: 'aws_api_gateway_stage',
  name: 'other',
  values: {
    stage_name: 'dev',
    rest_api_id: 'aws_api_gateway_rest_api.other_api',
  },
});

const catchAllSettings = [{ logging_level: 'INFO' }];

function run(allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: assessedStage,
    allResources,
  };
  return apigw006Control.run(factory.bind(context), context);
}

describe('APIGW-006 REQ-12 (Terraform): catch-all method settings pointing at another stage/API', () => {
  it('flags the assessed stage when the catch-all method settings reference a different stage (reference form)', () => {
    const methodSettings = resource({
      type: 'aws_api_gateway_method_settings',
      name: 'other_logging',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.other_api',
        stage_name: otherStage.address,
        method_path: '*/*',
        settings: catchAllSettings,
      },
    });

    const result = run([assessedStage, otherStage, methodSettings]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.assessed');
  });

  it('flags the assessed stage when the catch-all method settings name a different stage literally', () => {
    const methodSettings = resource({
      type: 'aws_api_gateway_method_settings',
      name: 'other_logging',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.other_api',
        stage_name: 'dev',
        method_path: '*/*',
        settings: catchAllSettings,
      },
    });

    const result = run([assessedStage, otherStage, methodSettings]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });

  it('flags the assessed stage when the catch-all method settings share the stage name but target a different API', () => {
    const sameNameStageOfOtherApi = resource({
      type: 'aws_api_gateway_stage',
      name: 'other_api_prod',
      values: {
        stage_name: 'prod',
        rest_api_id: 'aws_api_gateway_rest_api.other_api',
      },
    });
    const methodSettings = resource({
      type: 'aws_api_gateway_method_settings',
      name: 'other_api_logging',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.other_api',
        stage_name: sameNameStageOfOtherApi.address,
        method_path: '*/*',
        settings: catchAllSettings,
      },
    });

    const result = run([assessedStage, sameNameStageOfOtherApi, methodSettings]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });

  // Opposite outcome: identical catch-all settings, but attached to the assessed stage — the pass case
  // owned by the primary APIGW-006 behavior.
  it('does not flag the assessed stage when the catch-all method settings reference the assessed stage', () => {
    const methodSettings = resource({
      type: 'aws_api_gateway_method_settings',
      name: 'assessed_logging',
      values: {
        rest_api_id: 'aws_api_gateway_rest_api.api',
        stage_name: assessedStage.address,
        method_path: '*/*',
        settings: catchAllSettings,
      },
    });

    const result = run([assessedStage, otherStage, methodSettings]);

    expect(result).toBeNull();
  });
});
