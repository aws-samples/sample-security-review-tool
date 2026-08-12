import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (APIGW-002): A method that references a validator which enables ONLY parameter
 * validation, while the method declares no REQUIRED query string / header parameters,
 * must be flagged — parameter validation only checks required parameters, so nothing is
 * actually enforced.
 */

const factory = new Apigw002CfnAdapterFactory();

/** Validator that validates parameters only (body validation off). */
const parametersOnlyValidator: Resource = {
  Type: 'AWS::ApiGateway::RequestValidator',
  Properties: {
    RestApiId: 'RestApi',
    Name: 'params-only',
    ValidateRequestBody: false,
    ValidateRequestParameters: true,
  },
} as unknown as Resource;

function buildTemplate(methodProperties: Record<string, unknown>): Template {
  return {
    Resources: {
      RestApi: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'api' } },
      ParamsOnlyValidator: parametersOnlyValidator,
      Method: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          RestApiId: 'RestApi',
          ResourceId: 'ApiResource',
          AuthorizationType: 'AWS_IAM',
          // !Ref ParamsOnlyValidator resolves to the logical id string
          RequestModels: { 'application/json': 'Model' },
          RequestValidatorId: 'ParamsOnlyValidator',
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

describe('APIGW-002 REQ-13 (CloudFormation): parameter-only validator with nothing required', () => {
  it('flags a method whose parameter-only validator has no declared request parameters at all', () => {
    const result = run(buildTemplate({ HttpMethod: 'POST' }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('Method');
  });

  it('flags a method whose declared query string and header parameters are all optional', () => {
    const result = run(
      buildTemplate({
        HttpMethod: 'POST',
        RequestParameters: {
          'method.request.querystring.search': false,
          'method.request.header.X-Trace': false,
        },
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // Opposite outcome: the nearest input that flips the verdict — the same parameter is
  // present but marked REQUIRED, so parameter validation actually enforces something.
  it('does not flag a method that declares a required query string parameter', () => {
    const result = run(
      buildTemplate({
        HttpMethod: 'POST',
        RequestParameters: {
          'method.request.querystring.search': true,
          'method.request.header.X-Trace': false,
        },
      }),
    );

    expect(result).toBeNull();
  });

  // Opposite outcome: a required header parameter is equally sufficient.
  it('does not flag a method that declares a required header parameter', () => {
    const result = run(
      buildTemplate({
        HttpMethod: 'POST',
        RequestParameters: {
          'method.request.header.X-Trace': true,
        },
      }),
    );

    expect(result).toBeNull();
  });
});
