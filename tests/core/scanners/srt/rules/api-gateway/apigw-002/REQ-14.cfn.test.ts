import { describe, it, expect } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import type { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import type { CfnContext, Template, ScanResult } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002CfnAdapterFactory();

/**
 * Builds a template with a body-accepting POST method (RequestModels present) that references
 * a request validator. Only the validator's validation flags vary between tests.
 */
function buildTemplate(validateRequestBody: boolean, validateRequestParameters: boolean): Template {
  return {
    Resources: {
      BodyValidator: {
        Type: 'AWS::ApiGateway::RequestValidator',
        Properties: {
          RestApiId: 'Api',
          Name: 'params-only-validator',
          ValidateRequestBody: validateRequestBody,
          ValidateRequestParameters: validateRequestParameters,
        },
      },
      PostMethod: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          RestApiId: 'Api',
          ResourceId: 'ApiResource',
          HttpMethod: 'POST',
          AuthorizationType: 'AWS_IAM',
          // Method accepts a request body
          RequestModels: { 'application/json': 'OrderModel' },
          RequestParameters: {
            'method.request.querystring.tenantId': true,
            'method.request.header.X-Correlation-Id': true,
          },
          // !Ref BodyValidator collapses to the logical id string after preprocessing
          RequestModels: { 'application/json': 'Model' },
          RequestValidatorId: 'BodyValidator',
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

describe('APIGW-002 (CloudFormation) - parameter-only validation on a body-accepting method', () => {
  // Primary behavior owned by APIGW-002: body OR query/header parameter validation satisfies the rule.
  it('passes when a body-accepting method uses a validator that only validates query string and header parameters', () => {
    const result = run(buildTemplate(false, true));
    expect(result).toBeNull();
  });

  // Opposite outcome: the same method, but the validator enforces neither body nor parameter validation.
  it('flags the same method when the referenced validator validates neither body nor parameters', () => {
    const result = run(buildTemplate(false, false));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('PostMethod');
  });
});
