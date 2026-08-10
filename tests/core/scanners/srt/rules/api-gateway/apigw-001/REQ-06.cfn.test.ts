import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('APIGW-001 REQ-06 (CFN): Access logging destination is a Kinesis Data Firehose delivery stream', () => {
  it('passes for AWS::ApiGateway::Stage with Firehose delivery stream as access log destination', () => {
    const template: Template = {
      Resources: {
        FirehoseDeliveryStream: {
          Type: 'AWS::KinesisFirehose::DeliveryStream',
          Properties: {
            DeliveryStreamName: 'api-gw-access-logs-firehose',
          },
        },
        RestStage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: 'MyRestApi',
            AccessLogSetting: {
              DestinationArn: 'arn:aws:firehose:us-east-1:123456789012:deliverystream/api-gw-access-logs-firehose',
              Format: '$context.requestId',
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new Apigw001CfnAdapterFactory();
    const resource = template.Resources!['RestStage'];
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'RestStage',
    };
    const adapter = factory.bind(context);

    expect(adapter.hasAccessLogging()).toBe(true);
    expect(adapter.hasProperLogRetention()).toBe(true);

    const result = apigw001Control.run(adapter, context);
    expect(result).toBeNull();
  });

  it('passes for AWS::ApiGatewayV2::Stage with Firehose delivery stream as access log destination', () => {
    const template: Template = {
      Resources: {
        FirehoseDeliveryStream: {
          Type: 'AWS::KinesisFirehose::DeliveryStream',
          Properties: {
            DeliveryStreamName: 'api-gw-v2-access-logs-firehose',
          },
        },
        HttpStage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            StageName: '$default',
            ApiId: 'MyHttpApi',
            AccessLogSettings: {
              DestinationArn: 'arn:aws:firehose:us-east-1:123456789012:deliverystream/api-gw-v2-access-logs-firehose',
              Format: '$context.requestId',
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new Apigw001CfnAdapterFactory();
    const resource = template.Resources!['HttpStage'];
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'HttpStage',
    };
    const adapter = factory.bind(context);

    expect(adapter.hasAccessLogging()).toBe(true);
    expect(adapter.hasProperLogRetention()).toBe(true);

    const result = apigw001Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
