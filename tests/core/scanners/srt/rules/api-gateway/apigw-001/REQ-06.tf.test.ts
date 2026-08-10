import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('APIGW-001 REQ-06 (TF): Access logging destination is a Kinesis Data Firehose delivery stream', () => {
  it('passes for aws_api_gateway_stage with literal Firehose ARN destination', () => {
    const stage: TerraformResource = {
      type: 'aws_api_gateway_stage',
      name: 'prod',
      address: 'aws_api_gateway_stage.prod',
      values: {
        stage_name: 'prod',
        access_log_settings: [
          {
            destination_arn: 'arn:aws:firehose:us-east-1:123456789012:deliverystream/api-gw-access-logs-firehose',
            format: '$context.requestId',
          },
        ],
      },
    } as unknown as TerraformResource;

    const firehose: TerraformResource = {
      type: 'aws_kinesis_firehose_delivery_stream',
      name: 'logs',
      address: 'aws_kinesis_firehose_delivery_stream.logs',
      values: {
        name: 'api-gw-access-logs-firehose',
      },
    } as unknown as TerraformResource;

    const factory = new Apigw001TfAdapterFactory();
    expect(factory.appliesTo(stage.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources: [stage, firehose],
    };
    const adapter = factory.bind(context);

    expect(adapter.hasAccessLogging()).toBe(true);
    expect(adapter.hasProperLogRetention()).toBe(true);

    const result = apigw001Control.run(adapter, context);
    expect(result).toBeNull();
  });

  it('passes for aws_apigatewayv2_stage with reference-form Firehose destination', () => {
    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'default',
      address: 'aws_apigatewayv2_stage.default',
      values: {
        name: '$default',
        // Reference form: aws_kinesis_firehose_delivery_stream.logs.arn collapses to the address
        access_log_settings: [
          {
            destination_arn: 'aws_kinesis_firehose_delivery_stream.logs',
            format: '$context.requestId',
          },
        ],
      },
    } as unknown as TerraformResource;

    const firehose: TerraformResource = {
      type: 'aws_kinesis_firehose_delivery_stream',
      name: 'logs',
      address: 'aws_kinesis_firehose_delivery_stream.logs',
      values: {
        name: 'api-gw-v2-access-logs-firehose',
      },
    } as unknown as TerraformResource;

    const factory = new Apigw001TfAdapterFactory();
    expect(factory.appliesTo(stage.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources: [stage, firehose],
    };
    const adapter = factory.bind(context);

    expect(adapter.hasAccessLogging()).toBe(true);
    expect(adapter.hasProperLogRetention()).toBe(true);

    const result = apigw001Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
