import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002CfnAdapterFactory();

function buildTemplate(methodProperties: Record<string, unknown>, extraResources: Record<string, Resource> = {}): Template {
  return {
    Resources: {
      WildcardMethod: {
        Type: 'AWS::ApiGateway::Method',
        Properties: methodProperties,
      } as unknown as Resource,
      ...extraResources,
    },
  } as unknown as Template;
}

function scan(template: Template) {
  const resource = (template.Resources as Record<string, Resource>)['WildcardMethod'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'WildcardMethod',
  };
  const adapter = factory.bind(context) as Apigw002Adapter;
  return apigw002Control.run(adapter, context);
}

describe('APIGW-002 (CloudFormation) — wildcard ANY method without request validation', () => {
  // Primary behavior owned by APIGW-002: an ANY/wildcard method is a normal
  // request-accepting method, so the CORS preflight exclusion does not apply to it.
  it('flags an ANY method that references no request validator', () => {
    const result = scan(
      buildTemplate({
        RestApiId: 'RestApi',
        ResourceId: 'ApiResource',
        HttpMethod: 'ANY',
        AuthorizationType: 'NONE',
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('WildcardMethod');
  });

  it('flags a lower-cased "any" wildcard method that references no request validator', () => {
    const result = scan(
      buildTemplate({
        RestApiId: 'RestApi',
        ResourceId: 'ApiResource',
        HttpMethod: 'any',
        AuthorizationType: 'NONE',
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // Opposite outcome: identical wildcard method, but validation IS configured.
  it('does not flag an ANY method that references a validator enforcing body validation', () => {
    const result = scan(
      buildTemplate(
        {
          RestApiId: 'RestApi',
          ResourceId: 'ApiResource',
          HttpMethod: 'ANY',
          AuthorizationType: 'NONE',
          // !Ref BodyValidator resolves to the logical id string after preprocessing
          RequestModels: { 'application/json': 'Model' },
          RequestValidatorId: 'BodyValidator',
        },
        {
          BodyValidator: {
            Type: 'AWS::ApiGateway::RequestValidator',
            Properties: {
              RestApiId: 'RestApi',
              Name: 'body-validator',
              ValidateRequestBody: true,
              ValidateRequestParameters: false,
            },
          } as unknown as Resource,
        },
      ),
    );

    expect(result).toBeNull();
  });
});
