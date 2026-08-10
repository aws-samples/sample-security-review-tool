import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw001CfnAdapterFactory();

function runControl(template: Template, logicalId: string) {
  const resource = (template.Resources as Record<string, any>)[logicalId];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  const adapter = factory.bind(context);
  return apigw001Control.run(adapter, context);
}

describe('APIGW-001 REQ-04 (CFN): access log destination log group has zero/non-positive retention', () => {
  it('flags an AWS::ApiGateway::Stage when its in-template log group has RetentionInDays=0', () => {
    // After preprocessing, !GetAtt MyLogGroup.Arn collapses to "MyLogGroup".
    const template: Template = {
      Resources: {
        MyLogGroup: {
          Type: 'AWS::Logs::LogGroup',
          Properties: {
            LogGroupName: 'apigw-access-logs',
            RetentionInDays: 0,
          },
        },
        MyStage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: 'SomeApi',
            AccessLogSetting: {
              DestinationArn: 'MyLogGroup',
              Format: '$context.requestId',
            },
          },
        },
      },
    };

    const result = runControl(template, 'MyStage');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
    expect(result?.issue).toMatch(/retention/i);
  });

  it('flags an AWS::ApiGatewayV2::Stage when its in-template log group has RetentionInDays=-1', () => {
    const template: Template = {
      Resources: {
        AccessLogs: {
          Type: 'AWS::Logs::LogGroup',
          Properties: {
            LogGroupName: 'apigwv2-access-logs',
            RetentionInDays: -1,
          },
        },
        HttpStage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            StageName: 'prod',
            ApiId: 'SomeHttpApi',
            AccessLogSettings: {
              DestinationArn: 'AccessLogs',
              Format: '$context.requestId',
            },
          },
        },
      },
    };

    const result = runControl(template, 'HttpStage');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
    expect(result?.issue).toMatch(/retention/i);
  });
});
