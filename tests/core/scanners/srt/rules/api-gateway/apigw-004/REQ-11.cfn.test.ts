import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004CfnAdapterFactory();

function scan(template: Template, logicalId: string) {
  const resource = (template.Resources ?? {})[logicalId] as Resource;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

/**
 * REQ-11 (primary behavior owned by APIGW-004): when the authorization type of a
 * non-OPTIONS method is decided entirely by a condition that preprocessing leaves
 * unresolved (Fn::If stays an opaque object), the effective value is indeterminate
 * and the rule must not flag it.
 */
describe('APIGW-004 CloudFormation — indeterminate authorization type', () => {
  it('returns no finding when a non-OPTIONS REST method authorization type is an unresolved Fn::If', () => {
    const template: Template = {
      Resources: {
        Api: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'api' } },
        Method: {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            RestApiId: 'Api',
            HttpMethod: 'GET',
            AuthorizationType: { 'Fn::If': ['UseIamAuth', 'AWS_IAM', 'NONE'] },
          },
        },
      },
    } as unknown as Template;

    expect(scan(template, 'Method')).toBeNull();
  });

  it('returns no finding when a non-OPTIONS HTTP API route authorization type is an unresolved Fn::If', () => {
    const template: Template = {
      Resources: {
        HttpApi: { Type: 'AWS::ApiGatewayV2::Api', Properties: { Name: 'http-api', ProtocolType: 'HTTP' } },
        Route: {
          Type: 'AWS::ApiGatewayV2::Route',
          Properties: {
            ApiId: 'HttpApi',
            RouteKey: 'GET /items',
            AuthorizationType: { 'Fn::If': ['UseJwtAuth', 'JWT', 'NONE'] },
          },
        },
      },
    } as unknown as Template;

    expect(scan(template, 'Route')).toBeNull();
  });

  // Opposite outcome: identical fixture except the authorization type resolves to a
  // determinate, non-compliant literal — the rule must flag it.
  it('flags a non-OPTIONS REST method whose authorization type resolves to the literal NONE', () => {
    const template: Template = {
      Resources: {
        Api: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'api' } },
        Method: {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            RestApiId: 'Api',
            HttpMethod: 'GET',
            AuthorizationType: 'NONE',
          },
        },
      },
    } as unknown as Template;

    const result = scan(template, 'Method');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
  });
});
