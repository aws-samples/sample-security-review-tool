import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import type { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002CfnAdapterFactory();

interface ValidatorConfig {
  readonly ValidateRequestBody: boolean;
  readonly ValidateRequestParameters: boolean;
}

/**
 * Builds a template with one POST method that references a request validator
 * whose configuration is supplied by the test. `RequestValidatorId: !Ref Validator`
 * has already been preprocessed to the logical id string "Validator".
 */
function buildTemplate(validator: ValidatorConfig | undefined): Template {
  const method: Resource = {
    Type: 'AWS::ApiGateway::Method',
    Properties: {
      RestApiId: 'RestApi',
      ResourceId: 'ApiResource',
      HttpMethod: 'POST',
      AuthorizationType: 'AWS_IAM',
      RequestModels: { 'application/json': 'Model' },
      ...(validator ? { RequestValidatorId: 'Validator' } : {}),
      RequestParameters: {
        'method.request.querystring.customerId': true,
        'method.request.header.x-correlation-id': true,
      },
    },
  } as unknown as Resource;

  const resources: Record<string, Resource> = { ApiMethod: method };
  if (validator) {
    resources['Validator'] = {
      Type: 'AWS::ApiGateway::RequestValidator',
      Properties: {
        RestApiId: 'RestApi',
        Name: 'validator',
        ValidateRequestBody: validator.ValidateRequestBody,
        ValidateRequestParameters: validator.ValidateRequestParameters,
      },
    } as unknown as Resource;
  }

  return { Resources: resources } as unknown as Template;
}

function bind(template: Template): { adapter: Apigw002Adapter; context: CfnContext } {
  const resources = template.Resources as Record<string, Resource>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['ApiMethod']!,
    logicalId: 'ApiMethod',
  };
  return { adapter: factory.bind(context) as Apigw002Adapter, context };
}

describe('APIGW-002 REQ-03 (CloudFormation): parameter-only request validator', () => {
  // Primary behavior owned by this requirement: body OR query/header parameter
  // validation satisfies the rule.
  it('passes when the referenced validator validates required query/header parameters but not the body', () => {
    const template = buildTemplate({ ValidateRequestBody: false, ValidateRequestParameters: true });
    const { adapter, context } = bind(template);

    expect(apigw002Control.run(adapter, context)).toBeNull();
  });

  it('passes when the referenced validator validates the request body but not parameters', () => {
    const template = buildTemplate({ ValidateRequestBody: true, ValidateRequestParameters: false });
    const { adapter, context } = bind(template);

    expect(apigw002Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: the validator is still referenced, but its configuration
  // enforces neither body nor parameter validation, so nothing is validated.
  it('flags a method whose referenced validator validates neither the body nor parameters', () => {
    const template = buildTemplate({ ValidateRequestBody: false, ValidateRequestParameters: false });
    const { adapter, context } = bind(template);

    const result = apigw002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('ApiMethod');
  });
});
