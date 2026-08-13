import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.tf.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STAGE_TYPE = 'aws_api_gateway_stage';
const METHOD_SETTINGS_TYPE = 'aws_api_gateway_method_settings';

const stage: TerraformResource = {
  type: STAGE_TYPE,
  name: 'this',
  address: 'aws_api_gateway_stage.this',
  values: {
    stage_name: 'prod',
    rest_api_id: 'aws_api_gateway_rest_api.api',
  },
} as unknown as TerraformResource;

/** method_path "*​/*" is the catch-all scope covering every method and resource path. */
function methodSettings(stageNameValue: string, loggingLevel: string): TerraformResource {
  return {
    type: METHOD_SETTINGS_TYPE,
    name: 'all',
    address: 'aws_api_gateway_method_settings.all',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: stageNameValue,
      method_path: '*/*',
      settings: [{ logging_level: loggingLevel }],
    },
  } as unknown as TerraformResource;
}

function run(settings: TerraformResource) {
  const allResources = [stage, settings];
  const context: TfContext = { projectName: 'test-project', resource: stage, allResources };
  const factory = new Apigw006TfAdapterFactory();
  expect(factory.appliesTo(STAGE_TYPE)).toBe(true);
  const adapter = factory.bind(context) as Apigw006Adapter;
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 REQ-03 (Terraform): catch-all method settings with logging level ERROR', () => {
  // Primary behavior owned by this requirement.
  it('passes a stage whose catch-all method settings (reference form) use logging_level ERROR', () => {
    expect(run(methodSettings('aws_api_gateway_stage.this', 'ERROR'))).toBeNull();
  });

  it('passes a stage whose catch-all method settings (literal stage name) use logging_level ERROR', () => {
    expect(run(methodSettings('prod', 'ERROR'))).toBeNull();
  });

  // Opposite case: same catch-all settings block, but the logging level is present and not accepted.
  it('flags a stage whose catch-all method settings use logging_level OFF', () => {
    const result = run(methodSettings('aws_api_gateway_stage.this', 'OFF'));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.this');
    expect(result?.resourceType).toBe(STAGE_TYPE);
  });
});
