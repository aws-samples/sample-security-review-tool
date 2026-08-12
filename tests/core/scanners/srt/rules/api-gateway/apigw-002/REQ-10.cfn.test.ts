import { describe, it, expect } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (APIGW-002): A CORS preflight method (OPTIONS) with no request validation
 * configured must PASS — preflight requests carry no body and are explicitly excluded.
 */

const factory = new Apigw002CfnAdapterFactory();

function buildTemplate(httpMethod: string): Template {
  return {
    Resources: {
      MethodUnderTest: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: httpMethod,
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'RestApi' },
          AuthorizationType: 'NONE',
          // No RequestValidatorId at all
        },
      } as unknown as Resource,
      ApiResource: {
        Type: 'AWS::ApiGateway::Resource',
        Properties: { PathPart: 'items', RestApiId: 'RestApi' },
      } as unknown as Resource,
      RestApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: { Name: 'test-api' },
      } as unknown as Resource,
    },
  } as unknown as Template;
}

function run(httpMethod: string) {
  const template = buildTemplate(httpMethod);
  const resource = (template.Resources as Record<string, Resource>)['MethodUnderTest'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'MethodUnderTest',
  };
  return apigw002Control.run(factory.bind(context), context);
}

describe('APIGW-002 REQ-10 (CloudFormation): CORS preflight method exclusion', () => {
  it('passes an OPTIONS (CORS preflight) method that has no request validator', () => {
    expect(run('OPTIONS')).toBeNull();
  });

  it('passes an options (lower-cased preflight verb) method that has no request validator', () => {
    expect(run('options')).toBeNull();
  });

  // Opposite outcome: identical fixture, only the verb changes to a non-preflight verb.
  // The finding itself is owned by the "no request validator" requirement; asserted here
  // only to prove the preflight exclusion is what makes the OPTIONS case pass.
  it('flags a non-preflight POST method that has no request validator', () => {
    const result = run('POST');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('MethodUnderTest');
  });
});
