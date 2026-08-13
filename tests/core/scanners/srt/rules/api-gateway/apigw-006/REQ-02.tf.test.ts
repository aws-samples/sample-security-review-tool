import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.tf.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    rest_api_id: 'aws_api_gateway_rest_api.api',
    stage_name: 'prod',
    deployment_id: 'aws_api_gateway_deployment.dep',
  },
} as unknown as TerraformResource;

// Reference form — HCL wrote stage_name = aws_api_gateway_stage.prod.stage_name
function catchAllMethodSettings(loggingLevel: string): TerraformResource {
  return {
    type: 'aws_api_gateway_method_settings',
    name: 'all',
    address: 'aws_api_gateway_method_settings.all',
    values: {
      rest_api_id: 'aws_api_gateway_rest_api.api',
      stage_name: 'aws_api_gateway_stage.prod',
      // Catch-all: all HTTP methods on all resource paths
      method_path: '*/*',
      settings: [
        {
          metrics_enabled: true,
          logging_level: loggingLevel,
        },
      ],
    },
  } as unknown as TerraformResource;
}

function run(methodSettings: TerraformResource) {
  const allResources = [stage, methodSettings];
  const context: TfContext = {
    projectName: 'test-project',
    resource: stage,
    allResources,
  };
  const adapter = new Apigw006TfAdapterFactory().bind(context) as Apigw006Adapter;
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 REQ-02 (Terraform): catch-all method settings with INFO logging level', () => {
  // Primary behavior owned by this requirement: a catch-all
  // aws_api_gateway_method_settings (method_path "*/*") with logging_level INFO
  // satisfies the rule for every method of the referenced stage.
  it('passes when the catch-all method settings use logging_level INFO', () => {
    expect(run(catchAllMethodSettings('INFO'))).toBeNull();
  });

  // Opposite outcome: identical catch-all method settings still present, but the
  // logging level does not meet the accepted standard (INFO or ERROR).
  it('flags when the catch-all method settings use logging_level OFF', () => {
    const result = run(catchAllMethodSettings('OFF'));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });
});
