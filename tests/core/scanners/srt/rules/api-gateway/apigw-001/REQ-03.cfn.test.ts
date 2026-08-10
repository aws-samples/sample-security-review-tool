import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-03 (CloudFormation): API Gateway stage HAS access logging configured pointing
 * to a CloudWatch log group declared in the same template, but that log group has
 * NO retention configured (logs retained indefinitely).
 *
 * Expected behavior: flag — the rule mandates "proper retention", and a log group
 * without RetentionInDays causes log events to never expire, which fails the
 * retention portion of the requirement.
 */
describe('APIGW-001 (CFN) REQ-03: access logging present but log group has no retention', () => {
  const factory = new Apigw001CfnAdapterFactory();

  it('flags AWS::ApiGateway::Stage when its access log destination log group has no RetentionInDays', () => {
    const template: Template = {
      Resources: {
        AccessLogGroup: {
          Type: 'AWS::Logs::LogGroup',
          Properties: {
            LogGroupName: '/aws/apigateway/access-logs',
            // No RetentionInDays — logs retained indefinitely
          },
        },
        RestApi: {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: { Name: 'my-api' },
        },
        Stage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: 'RestApi',
            DeploymentId: 'Deployment',
            AccessLogSetting: {
              // After preprocessing, !GetAtt AccessLogGroup.Arn becomes "AccessLogGroup"
              DestinationArn: 'AccessLogGroup',
              Format: '$context.requestId',
            },
          },
        },
      },
    };

    const resource = template.Resources!['Stage']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'Stage',
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
    expect(result?.resourceName).toBe('Stage');
  });

  it('flags AWS::ApiGatewayV2::Stage when its access log destination log group has no RetentionInDays', () => {
    const template: Template = {
      Resources: {
        AccessLogGroup: {
          Type: 'AWS::Logs::LogGroup',
          Properties: {
            LogGroupName: '/aws/apigateway/v2-access-logs',
            // No RetentionInDays — logs retained indefinitely
          },
        },
        HttpApi: {
          Type: 'AWS::ApiGatewayV2::Api',
          Properties: { Name: 'my-http-api', ProtocolType: 'HTTP' },
        },
        Stage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            StageName: '$default',
            ApiId: 'HttpApi',
            AutoDeploy: true,
            AccessLogSettings: {
              DestinationArn: 'AccessLogGroup',
              Format: '$context.requestId',
            },
          },
        },
      },
    };

    const resource = template.Resources!['Stage']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'Stage',
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
    expect(result?.resourceType).toBe('AWS::ApiGatewayV2::Stage');
    expect(result?.resourceName).toBe('Stage');
  });
});
