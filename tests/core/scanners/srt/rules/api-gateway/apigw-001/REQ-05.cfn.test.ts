import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('APIGW-001 REQ-05 (CFN): external/pre-existing access log destination', () => {
  it('passes for AWS::ApiGateway::Stage when destination ARN refers to a log group not declared in the template', () => {
    const template: Template = {
      Resources: {
        ExternalLogStage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: 'SomeApi',
            DeploymentId: 'SomeDeployment',
            AccessLogSetting: {
              DestinationArn:
                'arn:aws:logs:us-east-1:999999999999:log-group:/aws/apigateway/external-preexisting-log-group',
              Format: '$context.requestId',
            },
          },
        },
      },
    };

    const factory = new Apigw001CfnAdapterFactory();
    const logicalId = 'ExternalLogStage';
    const resource = template.Resources![logicalId];
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const ctx: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);

    expect(result).toBeNull();
  });

  it('passes for AWS::ApiGatewayV2::Stage when destination ARN refers to a log group not declared in the template', () => {
    const template: Template = {
      Resources: {
        ExternalV2Stage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            ApiId: 'SomeHttpApi',
            StageName: '$default',
            AccessLogSettings: {
              DestinationArn:
                'arn:aws:logs:us-east-1:999999999999:log-group:/aws/apigateway/v2-external-log-group',
              Format: '$context.requestId',
            },
          },
        },
      },
    };

    const factory = new Apigw001CfnAdapterFactory();
    const logicalId = 'ExternalV2Stage';
    const resource = template.Resources![logicalId];
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const ctx: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);

    expect(result).toBeNull();
  });
});
