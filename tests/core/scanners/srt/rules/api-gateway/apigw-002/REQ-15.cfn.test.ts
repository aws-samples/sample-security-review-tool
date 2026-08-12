import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-15 (APIGW-002): A method whose verb carries no request body by definition, declaring no
 * body model and no query string or header parameters, must pass even with no request validator.
 * Nothing is declared for a validator to check, so no validator configuration could enforce
 * anything and there is no change worth asking the author to make.
 */

const factory = new Apigw002CfnAdapterFactory();

function buildTemplate(methodProperties: Record<string, unknown>): Template {
  return {
    Resources: {
      RestApi: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'api' } },
      Method: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          RestApiId: 'RestApi',
          ResourceId: 'ApiResource',
          AuthorizationType: 'AWS_IAM',
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

describe('APIGW-002 REQ-15 (CloudFormation): a method with no declared input needs no validator', () => {
  it('passes a GET that declares no body model and no parameters', () => {
    const result = run(buildTemplate({ HttpMethod: 'GET' }));

    expect(result).toBeNull();
  });

  it('passes a HEAD that declares no body model and no parameters', () => {
    const result = run(buildTemplate({ HttpMethod: 'HEAD' }));

    expect(result).toBeNull();
  });

  it('passes a DELETE that declares no body model and no parameters', () => {
    const result = run(buildTemplate({ HttpMethod: 'DELETE' }));

    expect(result).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict — the same GET now declares a
  // parameter, so there IS input a validator could enforce and its absence is a real finding.
  it('flags the same GET once it declares a query string parameter', () => {
    const result = run(
      buildTemplate({
        HttpMethod: 'GET',
        RequestParameters: { 'method.request.querystring.search': true },
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('Method');
  });

  // An optional parameter is still declared input, so the exemption does not apply.
  it('flags the same GET when its only declared parameter is optional', () => {
    const result = run(
      buildTemplate({
        HttpMethod: 'GET',
        RequestParameters: { 'method.request.header.X-Trace': false },
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // A path parameter is not input a validator can usefully check: it is part of the route, so a
  // request missing it never reaches the method. The exemption still applies.
  it('passes a GET whose only declared parameter is a path parameter', () => {
    const result = run(
      buildTemplate({
        HttpMethod: 'GET',
        RequestParameters: { 'method.request.path.proxy': true },
      }),
    );

    expect(result).toBeNull();
  });

  // A body-carrying verb is never exempt: declaring a model and validating it is a real fix.
  it('flags a POST that declares nothing, because a body can still arrive', () => {
    const result = run(buildTemplate({ HttpMethod: 'POST' }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });
});
