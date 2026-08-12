import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import type { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002CfnAdapterFactory();

/**
 * Template models one API with:
 *  - an enabled request validator (validates body)
 *  - a sibling method (POST) that references that validator
 *  - the assessed method (POST) whose RequestValidatorId is set per the test case
 */
function buildTemplate(assessedValidatorId?: unknown): Template {
  const assessedProps: Record<string, unknown> = {
    HttpMethod: 'POST',
    RequestModels: { 'application/json': 'Model' },
    ResourceId: 'ApiResource',
    RestApiId: 'RestApi',
    AuthorizationType: 'AWS_IAM',
  };
  if (assessedValidatorId !== undefined) assessedProps['RequestValidatorId'] = assessedValidatorId;

  return {
    Resources: {
      RestApi: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'api' } },
      EnabledValidator: {
        Type: 'AWS::ApiGateway::RequestValidator',
        Properties: {
          Name: 'body-validator',
          RestApiId: 'RestApi',
          ValidateRequestBody: true,
          ValidateRequestParameters: false,
        },
      },
      SiblingMethod: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'POST',
          ResourceId: 'ApiResource',
          RestApiId: 'RestApi',
          AuthorizationType: 'AWS_IAM',
          // sibling method is the one wired to the validator
          RequestModels: { 'application/json': 'Model' },
          RequestValidatorId: 'EnabledValidator',
        },
      },
      AssessedMethod: {
        Type: 'AWS::ApiGateway::Method',
        Properties: assessedProps,
      },
    },
  } as unknown as Template;
}

function assess(template: Template, logicalId = 'AssessedMethod') {
  const resources = (template.Resources ?? {}) as Record<string, Resource>;
  const resource = resources[logicalId]!;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = factory.bind(context) as Apigw002Adapter;
  return apigw002Control.run(adapter, context);
}

describe('APIGW-002 REQ-08 (CloudFormation): validator on a sibling method does not validate the assessed method', () => {
  // Primary behavior owned by APIGW-002: request validation is per-method.
  it('flags the assessed method when the enabled validator is only referenced by a sibling method', () => {
    const result = assess(buildTemplate(undefined));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('AssessedMethod');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
  });

  it('does not flag the sibling method that itself references the enabled validator', () => {
    const result = assess(buildTemplate(undefined), 'SiblingMethod');

    expect(result).toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict — the assessed method
  // references the same enabled validator instead of none.
  it('does not flag when the assessed method itself references the enabled validator', () => {
    const result = assess(buildTemplate('EnabledValidator'));

    expect(result).toBeNull();
  });
});
