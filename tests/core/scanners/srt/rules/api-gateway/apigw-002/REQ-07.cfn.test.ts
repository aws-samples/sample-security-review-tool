import { describe, expect, it } from 'vitest';
import { apigw002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.cfn.js';
import type { Apigw002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-002/apigw-002.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw002CfnAdapterFactory();

function scan(template: Template, logicalId: string): ScanResult | null {
  const resource = (template.Resources ?? {})[logicalId] as Resource;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = factory.bind(context) as Apigw002Adapter;
  return apigw002Control.run(adapter, context);
}

/**
 * REQ-07 (primary behavior owned by APIGW-002): a request validator with validation
 * enabled that belongs to a DIFFERENT API provides no coverage for the assessed
 * method, so the method must still be flagged.
 */
describe('APIGW-002 CloudFormation — validator with validation enabled belongs to a different API', () => {
  const templateWithUnrelatedValidator = (): Template => ({
    Resources: {
      ApiA: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'api-a' } },
      ApiB: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'api-b' } },
      ValidatorForApiB: {
        Type: 'AWS::ApiGateway::RequestValidator',
        Properties: {
          Name: 'validator-for-api-b',
          // !Ref ApiB resolves to the logical id string
          RestApiId: 'ApiB',
          ValidateRequestBody: true,
          ValidateRequestParameters: true,
        },
      },
      MethodOnApiA: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          RestApiId: 'ApiA',
          ResourceId: 'ApiA',
          HttpMethod: 'POST',
          RequestModels: { 'application/json': 'Model' },
          AuthorizationType: 'NONE',
          // No RequestValidatorId — the unrelated validator on ApiB is not referenced
        },
      },
    },
  } as unknown as Template);

  it('flags the method when the only enabled validator in the template belongs to another API and is not referenced', () => {
    const result = scan(templateWithUnrelatedValidator(), 'MethodOnApiA');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-002');
    expect(result?.resourceName).toBe('MethodOnApiA');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
  });

  // Opposite outcome: nearest input that flips the verdict — the method references a
  // validator of its OWN API with validation enabled.
  it('does not flag the method when it references an enabled validator belonging to its own API', () => {
    const template = templateWithUnrelatedValidator();
    (template.Resources as Record<string, Resource>)['ValidatorForApiA'] = {
      Type: 'AWS::ApiGateway::RequestValidator',
      Properties: {
        Name: 'validator-for-api-a',
        RestApiId: 'ApiA',
        ValidateRequestBody: true,
        ValidateRequestParameters: true,
      },
    } as unknown as Resource;
    const method = (template.Resources as Record<string, Resource>)['MethodOnApiA'] as Resource;
    (method.Properties as Record<string, unknown>)['RequestValidatorId'] = 'ValidatorForApiA';

    const result = scan(template, 'MethodOnApiA');

    expect(result).toBeNull();
  });
});
