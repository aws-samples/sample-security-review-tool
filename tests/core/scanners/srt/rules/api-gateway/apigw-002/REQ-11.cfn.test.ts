import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-11 (APIGW-002): when the effective request-validation configuration depends on a
 * condition that cannot be resolved at analysis time, the rule must return no finding.
 * The opposite-outcome test at the bottom belongs to the primary APIGW-002 behaviour
 * (a resolvable validator that enforces nothing IS a finding) and is included so this
 * file cannot be satisfied by a control that never flags.
 */

const factory = new Apigw002CfnAdapterFactory();

function run(template: Template, logicalId: string) {
  const resource = (template.Resources ?? {})[logicalId] as Resource;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  return apigw002Control.run(factory.bind(context), context);
}

describe('APIGW-002 REQ-11 (CloudFormation): undeterminable validation configuration', () => {
  it('returns no finding when the validator referenced by the method is chosen by an unresolved Fn::If', () => {
    const template: Template = {
      Resources: {
        StrictValidator: {
          Type: 'AWS::ApiGateway::RequestValidator',
          Properties: { RestApiId: 'RestApi', Name: 'strict', ValidateRequestBody: true },
        },
        LooseValidator: {
          Type: 'AWS::ApiGateway::RequestValidator',
          Properties: { RestApiId: 'RestApi', Name: 'loose', ValidateRequestBody: false, ValidateRequestParameters: false },
        },
        Method: {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            RestApiId: 'RestApi',
            ResourceId: 'ApiResource',
            HttpMethod: 'POST',
            RequestModels: { 'application/json': 'Model' },
            RequestValidatorId: { 'Fn::If': ['UseStrictValidation', 'StrictValidator', 'LooseValidator'] },
          },
        },
      },
    } as unknown as Template;

    expect(run(template, 'Method')).toBeNull();
  });

  it('returns no finding when the referenced validator flags are unresolved Fn::If values', () => {
    const template: Template = {
      Resources: {
        Validator: {
          Type: 'AWS::ApiGateway::RequestValidator',
          Properties: {
            RestApiId: 'RestApi',
            Name: 'conditional',
            ValidateRequestBody: { 'Fn::If': ['UseStrictValidation', true, false] },
            ValidateRequestParameters: { 'Fn::If': ['UseStrictValidation', true, false] },
          },
        },
        Method: {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            RestApiId: 'RestApi',
            ResourceId: 'ApiResource',
            HttpMethod: 'POST',
            RequestModels: { 'application/json': 'Model' },
            RequestValidatorId: 'Validator',
          },
        },
      },
    } as unknown as Template;

    expect(run(template, 'Method')).toBeNull();
  });

  it('returns no finding when the method validator reference itself is an unresolved cross-stack import', () => {
    const template: Template = {
      Resources: {
        Method: {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            RestApiId: 'RestApi',
            ResourceId: 'ApiResource',
            HttpMethod: 'POST',
            RequestModels: { 'application/json': 'Model' },
            RequestValidatorId: { 'Fn::ImportValue': 'SharedValidatorId' },
          },
        },
      },
    } as unknown as Template;

    expect(run(template, 'Method')).toBeNull();
  });

  // OPPOSITE OUTCOME — owned by the primary APIGW-002 behaviour: the same method with a
  // fully determinable validator that validates neither body nor parameters must be flagged.
  it('flags the method when the referenced validator resolvably enforces nothing', () => {
    const template: Template = {
      Resources: {
        Validator: {
          Type: 'AWS::ApiGateway::RequestValidator',
          Properties: {
            RestApiId: 'RestApi',
            Name: 'conditional',
            ValidateRequestBody: false,
            ValidateRequestParameters: false,
          },
        },
        Method: {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            RestApiId: 'RestApi',
            ResourceId: 'ApiResource',
            HttpMethod: 'POST',
            RequestModels: { 'application/json': 'Model' },
            RequestValidatorId: 'Validator',
          },
        },
      },
    } as unknown as Template;

    const result = run(template, 'Method');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });
});
