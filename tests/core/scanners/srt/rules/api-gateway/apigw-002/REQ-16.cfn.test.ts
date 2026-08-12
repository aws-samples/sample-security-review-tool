import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-16 (APIGW-002): A method that enables body validation while declaring no request body model
 * must be flagged. API Gateway validates the payload against the model configured for the request
 * content type, and performs no validation when no matching content type is found, so the flag
 * alone enforces nothing while the configuration reads as validated.
 */

const factory = new Apigw002CfnAdapterFactory();

function validator(properties: Record<string, unknown>): Resource {
  return {
    Type: 'AWS::ApiGateway::RequestValidator',
    Properties: { RestApiId: 'RestApi', Name: 'validator', ...properties },
  } as unknown as Resource;
}

function buildTemplate(methodProperties: Record<string, unknown>, validatorProperties: Record<string, unknown>): Template {
  return {
    Resources: {
      RestApi: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'api' } },
      Validator: validator(validatorProperties),
      Method: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          RestApiId: 'RestApi',
          ResourceId: 'ApiResource',
          AuthorizationType: 'AWS_IAM',
          HttpMethod: 'POST',
          RequestValidatorId: 'Validator',
          ...methodProperties,
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template) {
  const resources = (template.Resources ?? {}) as Record<string, Resource>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['Method'] as Resource,
    logicalId: 'Method',
  };
  return apigw002Control.run(factory.bind(context), context);
}

const bodyOnly = { ValidateRequestBody: true, ValidateRequestParameters: false };
const bodyAndParameters = { ValidateRequestBody: true, ValidateRequestParameters: true };

describe('APIGW-002 REQ-16 (CloudFormation): body validation with no model declared', () => {
  it('flags a method that enables body validation but declares no request body model', () => {
    const result = run(buildTemplate({}, bodyOnly));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('Method');
  });

  it('flags a method whose declared request body model map is empty', () => {
    const result = run(buildTemplate({ RequestModels: {} }, bodyOnly));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // Parameter validation alone cannot rescue it while nothing is marked required.
  it('flags a method with body and parameter validation whose parameters are all optional', () => {
    const result = run(
      buildTemplate({ RequestParameters: { 'method.request.querystring.search': false } }, bodyAndParameters),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // Opposite outcome: the nearest input that flips the verdict — the same method now declares a
  // model, so the enabled body validation has a schema to enforce.
  it('does not flag the same method once it declares a request body model', () => {
    const result = run(buildTemplate({ RequestModels: { 'application/json': 'Model' } }, bodyOnly));

    expect(result).toBeNull();
  });

  // Enforced parameter validation is sufficient on its own, model or not.
  it('does not flag when a required parameter is validated alongside the unusable body flag', () => {
    const result = run(
      buildTemplate({ RequestParameters: { 'method.request.querystring.search': true } }, bodyAndParameters),
    );

    expect(result).toBeNull();
  });
});
