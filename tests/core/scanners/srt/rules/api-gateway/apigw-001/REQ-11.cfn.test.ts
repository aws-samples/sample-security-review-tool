import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('APIGW-001 CloudFormation - REQ-11: log group retention is unresolvable', () => {
  it('passes when AWS::ApiGateway::Stage references an in-template log group whose RetentionInDays is an unresolved Fn::If', () => {
    const template: Template = {
      Resources: {
        AccessLogGroup: {
          Type: 'AWS::Logs::LogGroup',
          Properties: {
            LogGroupName: '/aws/apigateway/access-logs',
            // Unresolved intrinsic — preprocessing leaves Fn::If as an object.
            RetentionInDays: {
              'Fn::If': ['IsProd', 365, 30],
            },
          },
        },
        ApiStage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: 'MyApi',
            AccessLogSetting: {
              // !GetAtt AccessLogGroup.Arn collapses to "AccessLogGroup".
              DestinationArn: 'AccessLogGroup',
              Format: '$context.requestId',
            },
          },
        },
      },
    };

    const factory = new Apigw001CfnAdapterFactory();
    const resource = template.Resources!['ApiStage'];
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'ApiStage',
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);
    expect(result).toBeNull();
  });

  it('passes when AWS::ApiGatewayV2::Stage references an in-template log group whose RetentionInDays is an unresolved Fn::ImportValue', () => {
    const template: Template = {
      Resources: {
        AccessLogGroup: {
          Type: 'AWS::Logs::LogGroup',
          Properties: {
            LogGroupName: '/aws/apigateway/v2-access-logs',
            // Unresolved intrinsic — Fn::ImportValue stays as an object.
            RetentionInDays: {
              'Fn::ImportValue': 'SharedRetention',
            },
          },
        },
        HttpStage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            StageName: '$default',
            ApiId: 'MyHttpApi',
            AccessLogSettings: {
              DestinationArn: 'AccessLogGroup',
              Format: '$context.requestId',
            },
          },
        },
      },
    };

    const factory = new Apigw001CfnAdapterFactory();
    const resource = template.Resources!['HttpStage'];
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'HttpStage',
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
