import { describe, it, expect } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002CfnAdapterFactory();

function buildTemplate(methodProps: Record<string, unknown>): Template {
  return {
    Resources: {
      RestApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: { Name: 'test-api' },
      },
      ApiResource: {
        Type: 'AWS::ApiGateway::Resource',
        Properties: { RestApiId: 'RestApi', PathPart: 'items', ParentId: 'RestApi' },
      },
      // Validator exists in the template; whether the method references it is what varies.
      Validator: {
        Type: 'AWS::ApiGateway::RequestValidator',
        Properties: {
          RestApiId: 'RestApi',
          Name: 'body-validator',
          ValidateRequestBody: true,
          ValidateRequestParameters: true,
        },
      },
      Method: {
        Type: 'AWS::ApiGateway::Method',
        Properties: methodProps,
      },
    },
  } as unknown as Template;
}

function run(template: Template) {
  const resource = (template.Resources as Record<string, Resource>)['Method'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Method',
  };
  return apigw002Control.run(factory.bind(context) as never, context);
}

describe('APIGW-002 REQ-01 (CloudFormation): method with no request validator reference', () => {
  it('flags a non-preflight method that references no request validator', () => {
    const result = run(
      buildTemplate({
        RestApiId: 'RestApi',
        ResourceId: 'ApiResource',
        HttpMethod: 'POST',
        AuthorizationType: 'NONE',
        Integration: { Type: 'AWS_PROXY', IntegrationHttpMethod: 'POST' },
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
    expect(result?.resourceName).toBe('Method');
  });

  // Opposite outcome: nearest input that flips the verdict — the same method WITH a
  // request validator reference. Primary behavior (validator present => pass) is owned
  // by the sibling requirement; this case exists to prove the file discriminates.
  it('does not flag the same method when it references a request validator', () => {
    const result = run(
      buildTemplate({
        RestApiId: 'RestApi',
        ResourceId: 'ApiResource',
        HttpMethod: 'POST',
        AuthorizationType: 'NONE',
        // !Ref Validator resolves to the logical ID string after preprocessing
        RequestModels: { 'application/json': 'Model' },
        RequestValidatorId: 'Validator',
        Integration: { Type: 'AWS_PROXY', IntegrationHttpMethod: 'POST' },
      }),
    );

    expect(result).toBeNull();
  });
});
