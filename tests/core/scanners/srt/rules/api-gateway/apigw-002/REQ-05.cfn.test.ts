import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import type { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (APIGW-002): A method that references an existing request validator which
 * specifies NO validation flags at all must be flagged — both ValidateRequestBody and
 * ValidateRequestParameters default to false, so the validator validates nothing.
 */

const factory = new Apigw002CfnAdapterFactory();

function buildTemplate(validatorProperties: Record<string, unknown>): Template {
  return {
    Resources: {
      RestApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: { Name: 'demo-api' },
      },
      // Ref/GetAtt collapse to the logical id string, so the method points at "Validator".
      Validator: {
        Type: 'AWS::ApiGateway::RequestValidator',
        Properties: validatorProperties,
      },
      PostMethod: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'POST',
          RestApiId: 'RestApi',
          ResourceId: 'RestApi',
          AuthorizationType: 'AWS_IAM',
          RequestModels: { 'application/json': 'Model' },
          RequestValidatorId: 'Validator',
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template): ScanResult | null {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['PostMethod'],
    logicalId: 'PostMethod',
  };
  const adapter = factory.bind(context) as Apigw002Adapter;
  return apigw002Control.run(adapter, context);
}

describe('APIGW-002 REQ-05 (CloudFormation): referenced validator with no validation flags', () => {
  it('flags a method whose referenced validator omits both validation flags', () => {
    const result = run(buildTemplate({ Name: 'no-flags-validator', RestApiId: 'RestApi' }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('PostMethod');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
  });

  it('flags a method whose referenced validator omits only ValidateRequestParameters while body validation is false', () => {
    const result = run(
      buildTemplate({ Name: 'partial-validator', RestApiId: 'RestApi', ValidateRequestBody: false }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // Opposite outcome: the nearest input that flips the verdict — the validator is still
  // referenced and present, but it actually enables body validation.
  it('does not flag a method whose referenced validator enables body validation', () => {
    const result = run(
      buildTemplate({ Name: 'body-validator', RestApiId: 'RestApi', ValidateRequestBody: true }),
    );

    expect(result).toBeNull();
  });
});
