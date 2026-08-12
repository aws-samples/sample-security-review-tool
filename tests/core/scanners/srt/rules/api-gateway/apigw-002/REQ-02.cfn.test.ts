import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002CfnAdapterFactory();

/**
 * Builds a template containing a RequestValidator whose configuration enables
 * request body validation, plus a single method that points at it.
 * `validatorId` is written the way parseCfnTemplate would leave a !Ref:
 * the logical id string of the validator resource (or '' for no reference).
 */
function buildTemplate(validatorId: string): Template {
  return {
    Resources: {
      BodyValidator: {
        Type: 'AWS::ApiGateway::RequestValidator',
        Properties: {
          RestApiId: 'RestApi',
          Name: 'body-validator',
          ValidateRequestBody: true,
          ValidateRequestParameters: false,
        },
      },
      PostMethod: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          RestApiId: 'RestApi',
          ResourceId: 'ApiResource',
          HttpMethod: 'POST',
          AuthorizationType: 'AWS_IAM',
          RequestModels: { 'application/json': 'Model' },
          RequestValidatorId: validatorId,
          RequestModels: { 'application/json': 'RequestModel' },
        },
      },
    },
  } as unknown as Template;
}

function contextFor(template: Template, logicalId: string): CfnContext {
  const resource = (template.Resources as Record<string, Resource>)[logicalId];
  return { stackName: 'test-stack', template, resource, logicalId };
}

function run(template: Template, logicalId: string) {
  const context = contextFor(template, logicalId);
  return apigw002Control.run(factory.bind(context), context);
}

describe('APIGW-002 (CloudFormation) - method references a request validator that validates the request body', () => {
  // Primary behaviour owned by this requirement (REQ-02).
  it('passes when the method references a validator whose configuration enables request body validation', () => {
    const result = run(buildTemplate('BodyValidator'), 'PostMethod');

    expect(result).toBeNull();
  });

  // Opposite outcome: the RequestValidatorId is still present but references nothing,
  // so no validation is enforced and the control must flag the method.
  it('flags the method when the RequestValidatorId is present but empty, referencing no validator', () => {
    const result = run(buildTemplate(''), 'PostMethod');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('PostMethod');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
  });
});
