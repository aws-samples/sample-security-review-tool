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

  /**
   * `RetentionInDays: !Ref RetentionParameter` on a parameter with no Default reaches
   * the rule as the string 'DEFAULT', which preprocessing substitutes for a Ref it
   * cannot resolve. The retention is chosen at deploy time and cannot be judged here.
   */
  const evaluateRetention = (retention: unknown) => {
    const template: Template = {
      Resources: {
        AccessLogGroup: {
          Type: 'AWS::Logs::LogGroup',
          Properties: { LogGroupName: '/aws/apigateway/access-logs', RetentionInDays: retention },
        },
        ApiStage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: 'MyApi',
            AccessLogSetting: { DestinationArn: 'AccessLogGroup', Format: '$context.requestId' },
          },
        },
      },
    } as unknown as Template;

    const resource = template.Resources!['ApiStage'];
    const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId: 'ApiStage' };
    return apigw001Control.run(new Apigw001CfnAdapterFactory().bind(context), context);
  };

  it("passes when RetentionInDays is the unresolved-parameter placeholder 'DEFAULT'", () => {
    expect(evaluateRetention('DEFAULT')).toBeNull();
  });

  it('passes when a resolved parameter default arrives as a numeric string', () => {
    expect(evaluateRetention('30')).toBeNull();
  });

  it('still flags a non-numeric retention string (REQ-12)', () => {
    expect(evaluateRetention('not-a-number')?.check_id).toBe('APIGW-001');
  });

  it('still flags a zero retention supplied as a string (REQ-04)', () => {
    expect(evaluateRetention('0')?.check_id).toBe('APIGW-001');
  });
});
