import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (CloudFormation):
 * API Gateway stage has access logging enabled and points to an in-template log group,
 * but the log group's RetentionInDays is set to a value the rule does not recognize as
 * a valid CloudWatch retention period (e.g., a non-numeric or otherwise invalid value).
 *
 * Expected: flag — invalid retention will not produce intended retention behavior.
 */
describe('APIGW-001 CFN — invalid log retention value flags as missing retention', () => {
  function runControlOnStage(template: Template, logicalId: string) {
    const factory = new Apigw001CfnAdapterFactory();
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

  it('flags AWS::ApiGateway::Stage when log group RetentionInDays is a non-numeric string', () => {
    const template: Template = {
      Resources: {
        AccessLogGroup: {
          Type: 'AWS::Logs::LogGroup',
          Properties: {
            LogGroupName: '/aws/apigw/access-logs',
            // Invalid: non-numeric value will not be honored as a retention period.
            RetentionInDays: 'not-a-number',
          },
        },
        RestStage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            AccessLogSetting: {
              DestinationArn: 'AccessLogGroup',
              Format: '$context.requestId',
            },
          },
        },
      },
    } as unknown as Template;

    const result = runControlOnStage(template, 'RestStage');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
    expect(result?.issue).toMatch(/retention/i);
  });

  it('flags AWS::ApiGatewayV2::Stage when log group RetentionInDays is an invalid object value', () => {
    const template: Template = {
      Resources: {
        V2AccessLogGroup: {
          Type: 'AWS::Logs::LogGroup',
          Properties: {
            LogGroupName: '/aws/apigw/v2-access-logs',
            // Invalid: a leftover unresolved intrinsic-shaped value is not a real retention period.
            RetentionInDays: { 'Fn::If': ['SomeCondition', 7, 'invalid'] },
          },
        },
        HttpStage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            StageName: 'prod',
            ApiId: 'SomeApi',
            AccessLogSettings: {
              DestinationArn: 'V2AccessLogGroup',
              Format: '$context.requestId',
            },
          },
        },
      },
    } as unknown as Template;

    const result = runControlOnStage(template, 'HttpStage');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
    expect(result?.issue).toMatch(/retention/i);
  });
});
