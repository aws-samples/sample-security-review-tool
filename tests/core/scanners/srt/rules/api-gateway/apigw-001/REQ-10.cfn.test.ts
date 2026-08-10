import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('APIGW-001 CFN — REQ-10: V2 stage with access logging to in-template log group with explicit non-zero retention', () => {
  it('passes when AWS::ApiGatewayV2::Stage references an in-template log group with explicit RetentionInDays > 0', () => {
    const template: Template = {
      Resources: {
        AccessLogs: {
          Type: 'AWS::Logs::LogGroup',
          Properties: {
            LogGroupName: '/aws/apigateway/my-api-access',
            RetentionInDays: 30,
          },
        },
        MyV2Stage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            ApiId: 'MyApi',
            StageName: 'prod',
            AccessLogSettings: {
              // !GetAtt AccessLogs.Arn collapses to the logical id "AccessLogs" after preprocessing.
              DestinationArn: 'AccessLogs',
              Format: '$context.requestId',
            },
          },
        },
      },
    };

    const factory = new Apigw001CfnAdapterFactory();
    const resource = template.Resources!['MyV2Stage'];
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyV2Stage',
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
