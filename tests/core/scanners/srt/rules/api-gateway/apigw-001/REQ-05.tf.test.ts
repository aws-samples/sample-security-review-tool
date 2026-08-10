import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('APIGW-001 REQ-05 (TF): external/pre-existing access log destination', () => {
  it('passes for aws_api_gateway_stage when destination_arn is a literal ARN not declared in the plan', () => {
    const stage: TerraformResource = {
      type: 'aws_api_gateway_stage',
      name: 'prod',
      address: 'aws_api_gateway_stage.prod',
      values: {
        stage_name: 'prod',
        access_log_settings: [
          {
            destination_arn:
              'arn:aws:logs:us-east-1:999999999999:log-group:/aws/apigateway/external-preexisting',
            format: '$context.requestId',
          },
        ],
      },
    } as TerraformResource;

    const allResources = [stage];
    const factory = new Apigw001TfAdapterFactory();
    expect(factory.appliesTo(stage.type)).toBe(true);

    const ctx: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources,
    };
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);

    expect(result).toBeNull();
  });

  it('passes for aws_apigatewayv2_stage when destination_arn references an external (non-planned) resource address', () => {
    // Reference form: HCL had `destination_arn = data.aws_cloudwatch_log_group.external.arn`
    // The plan reader would collapse this to the data source / external address string,
    // which is not present in the plan as a managed aws_cloudwatch_log_group resource.
    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'default',
      address: 'aws_apigatewayv2_stage.default',
      values: {
        name: '$default',
        access_log_settings: [
          {
            destination_arn: 'data.aws_cloudwatch_log_group.external',
            format: '$context.requestId',
          },
        ],
      },
    } as TerraformResource;

    const allResources = [stage];
    const factory = new Apigw001TfAdapterFactory();
    expect(factory.appliesTo(stage.type)).toBe(true);

    const ctx: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources,
    };
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);

    expect(result).toBeNull();
  });
});
