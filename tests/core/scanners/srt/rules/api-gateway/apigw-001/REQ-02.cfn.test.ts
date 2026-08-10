import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(template: Template, logicalId: string): CfnContext {
  const resource = template.Resources![logicalId]!;
  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
}

describe('APIGW-001 REQ-02 (CFN): access logging configured with in-template log group destination and non-zero retention', () => {
  it('passes for AWS::ApiGateway::Stage with AccessLogSetting pointing to an in-template log group with explicit retention', () => {
    const template: Template = {
      Resources: {
        AccessLogs: {
          Type: 'AWS::Logs::LogGroup',
          Properties: {
            LogGroupName: '/aws/apigateway/access',
            RetentionInDays: 30,
          },
        },
        ApiStage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: 'MyApi',
            // After preprocessing, !GetAtt AccessLogs.Arn becomes "AccessLogs"
            AccessLogSetting: {
              DestinationArn: 'AccessLogs',
              Format: '$context.requestId',
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new Apigw001CfnAdapterFactory();
    const ctx = buildContext(template, 'ApiStage');
    expect(factory.appliesTo('AWS::ApiGateway::Stage')).toBe(true);
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);
    expect(result).toBeNull();
  });

  it('passes for AWS::ApiGatewayV2::Stage with AccessLogSettings pointing to an in-template log group with explicit retention', () => {
    const template: Template = {
      Resources: {
        AccessLogs: {
          Type: 'AWS::Logs::LogGroup',
          Properties: {
            LogGroupName: '/aws/apigateway/v2-access',
            RetentionInDays: 90,
          },
        },
        HttpApiStage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            StageName: '$default',
            ApiId: 'MyHttpApi',
            AccessLogSettings: {
              DestinationArn: 'AccessLogs',
              Format: '$context.requestId',
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new Apigw001CfnAdapterFactory();
    const ctx = buildContext(template, 'HttpApiStage');
    expect(factory.appliesTo('AWS::ApiGatewayV2::Stage')).toBe(true);
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);
    expect(result).toBeNull();
  });
});
