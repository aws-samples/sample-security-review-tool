import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('APIGW-001 / CloudFormation / REQ-01: stage with no access logging configuration', () => {
  it('flags an AWS::ApiGateway::Stage that has no AccessLogSetting', () => {
    const template: Template = {
      Resources: {
        MyStage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: 'MyApi',
            DeploymentId: 'MyDeployment',
          },
        },
      },
    };

    const factory = new Apigw001CfnAdapterFactory();
    const resource = template.Resources!['MyStage'];
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyStage',
    };

    expect(factory.appliesTo(resource.Type)).toBe(true);

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('APIGW-001');
    expect(result!.resourceType).toBe('AWS::ApiGateway::Stage');
    expect(result!.resourceName).toBe('MyStage');
    expect(result!.status).toBe('Open');
  });

  it('flags an AWS::ApiGatewayV2::Stage that has no AccessLogSettings', () => {
    const template: Template = {
      Resources: {
        MyV2Stage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            StageName: 'prod',
            ApiId: 'MyApi',
          },
        },
      },
    };

    const factory = new Apigw001CfnAdapterFactory();
    const resource = template.Resources!['MyV2Stage'];
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyV2Stage',
    };

    expect(factory.appliesTo(resource.Type)).toBe(true);

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('APIGW-001');
    expect(result!.resourceType).toBe('AWS::ApiGatewayV2::Stage');
    expect(result!.resourceName).toBe('MyV2Stage');
    expect(result!.status).toBe('Open');
  });
});
