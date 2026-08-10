import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('APIGW-001 / REQ-09 (CFN): V2 stage has no access log settings configured', () => {
  const factory = new Apigw001CfnAdapterFactory();

  it('flags an AWS::ApiGatewayV2::Stage with no AccessLogSettings property', () => {
    const template: Template = {
      Resources: {
        HttpStage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            ApiId: 'HttpApi',
            StageName: '$default',
            AutoDeploy: true,
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['HttpStage']!,
      logicalId: 'HttpStage',
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('APIGW-001');
    expect(result!.resourceType).toBe('AWS::ApiGatewayV2::Stage');
    expect(result!.resourceName).toBe('HttpStage');
    expect(result!.issue).toMatch(/access logging/i);
  });

  it('flags an AWS::ApiGatewayV2::Stage when AccessLogSettings is an empty object', () => {
    const template: Template = {
      Resources: {
        WsStage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            ApiId: 'WsApi',
            StageName: 'prod',
            AccessLogSettings: {},
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['WsStage']!,
      logicalId: 'WsStage',
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('APIGW-001');
    expect(result!.issue).toMatch(/access logging/i);
  });
});
