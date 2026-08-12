import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import type { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

// REQ-06 (owner of this behavior): an API method whose request validator reference is
// empty/blank identifies no validator, so it must be flagged exactly like a method with
// no validation at all.

const factory = new Apigw002CfnAdapterFactory();

function buildTemplate(validatorId: unknown, includeValidator: boolean): Template {
  const template: Template = {
    Resources: {
      ApiMethod: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'POST',
          RestApiId: 'RestApi',
          ResourceId: 'ApiResource',
          AuthorizationType: 'AWS_IAM',
          RequestModels: { 'application/json': 'Model' },
          RequestValidatorId: validatorId,
        },
      },
    },
  } as unknown as Template;

  if (includeValidator) {
    (template.Resources as Record<string, unknown>)['BodyValidator'] = {
      Type: 'AWS::ApiGateway::RequestValidator',
      Properties: {
        Name: 'body-validator',
        RestApiId: 'RestApi',
        ValidateRequestBody: true,
        ValidateRequestParameters: false,
      },
    };
  }

  return template;
}

function run(validatorId: unknown, includeValidator = false): ScanResult | null {
  const template = buildTemplate(validatorId, includeValidator);
  const resource = (template.Resources as Record<string, unknown>)['ApiMethod'] as CfnContext['resource'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'ApiMethod',
  };
  const adapter = factory.bind(context) as Apigw002Adapter;
  return apigw002Control.run(adapter, context);
}

describe('APIGW-002 REQ-06 (CloudFormation): blank request validator reference', () => {
  it('flags a method whose RequestValidatorId is an empty string', () => {
    const result = run('');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('ApiMethod');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
  });

  it('flags a method whose RequestValidatorId is whitespace only', () => {
    const result = run('   ');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
  });

  // Opposite outcome: same method, but the validator reference is present and non-blank,
  // resolving to a validator that validates the request body.
  it('does not flag a method whose RequestValidatorId names a real enforcing validator', () => {
    const result = run('BodyValidator', true);
    expect(result).toBeNull();
  });
});
