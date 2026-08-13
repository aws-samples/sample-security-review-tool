import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004CfnAdapterFactory();

function run(template: Template, logicalId: string): ScanResult | null {
  const resource = (template.Resources as Record<string, Resource>)[logicalId];
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

/**
 * REQ-09 (APIGW-004): a non-OPTIONS method whose authorizer belongs to a DIFFERENT API
 * is not actually authorized, so the control must flag it.
 *
 * Note: !Ref / !GetAtt values are shown here already resolved to logical ID strings,
 * exactly as parseCfnTemplate leaves them.
 */
describe('APIGW-004 REQ-09 (CloudFormation): authorizer scoped to another API', () => {
  it('flags a REST API method whose CUSTOM authorizer belongs to a different REST API', () => {
    const template: Template = {
      Resources: {
        ApiA: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'api-a' } },
        ApiB: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'api-b' } },
        AuthorizerForApiB: {
          Type: 'AWS::ApiGateway::Authorizer',
          Properties: { Name: 'lambda-auth', Type: 'TOKEN', RestApiId: 'ApiB' },
        },
        MethodOnApiA: {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            HttpMethod: 'GET',
            RestApiId: 'ApiA',
            ResourceId: 'ApiAResource',
            AuthorizationType: 'CUSTOM',
            AuthorizerId: 'AuthorizerForApiB',
          },
        },
      },
    } as unknown as Template;

    const result = run(template, 'MethodOnApiA');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('MethodOnApiA');
  });

  it('flags an HTTP API route whose JWT authorizer belongs to a different HTTP API', () => {
    const template: Template = {
      Resources: {
        HttpApiA: { Type: 'AWS::ApiGatewayV2::Api', Properties: { Name: 'http-a', ProtocolType: 'HTTP' } },
        HttpApiB: { Type: 'AWS::ApiGatewayV2::Api', Properties: { Name: 'http-b', ProtocolType: 'HTTP' } },
        JwtAuthorizerForApiB: {
          Type: 'AWS::ApiGatewayV2::Authorizer',
          Properties: { Name: 'jwt-auth', AuthorizerType: 'JWT', ApiId: 'HttpApiB' },
        },
        RouteOnApiA: {
          Type: 'AWS::ApiGatewayV2::Route',
          Properties: {
            ApiId: 'HttpApiA',
            RouteKey: 'GET /items',
            AuthorizationType: 'JWT',
            AuthorizerId: 'JwtAuthorizerForApiB',
          },
        },
      },
    } as unknown as Template;

    const result = run(template, 'RouteOnApiA');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('RouteOnApiA');
  });

  // Opposite outcome: identical fixture except the authorizer is scoped to the SAME API,
  // which satisfies the authorization requirement owned by APIGW-004.
  it('does not flag a method whose CUSTOM authorizer belongs to the same REST API', () => {
    const template: Template = {
      Resources: {
        ApiA: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'api-a' } },
        ApiB: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'api-b' } },
        AuthorizerForApiA: {
          Type: 'AWS::ApiGateway::Authorizer',
          Properties: { Name: 'lambda-auth', Type: 'TOKEN', RestApiId: 'ApiA' },
        },
        MethodOnApiA: {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            HttpMethod: 'GET',
            RestApiId: 'ApiA',
            ResourceId: 'ApiAResource',
            AuthorizationType: 'CUSTOM',
            AuthorizerId: 'AuthorizerForApiA',
          },
        },
      },
    } as unknown as Template;

    expect(run(template, 'MethodOnApiA')).toBeNull();
  });
});
