import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004CfnAdapterFactory();

/**
 * Builds a template containing a catch-all route/method plus the authorizers it may reference.
 * Values are written post-`parseCfnTemplate` (a `!Ref Authorizer` collapses to "Authorizer").
 */
function buildTemplate(catchAll: Record<string, Resource>): Template {
  return {
    Resources: {
      HttpApi: { Type: 'AWS::ApiGatewayV2::Api', Properties: { Name: 'catch-all-api', ProtocolType: 'HTTP' } },
      JwtAuthorizer: {
        Type: 'AWS::ApiGatewayV2::Authorizer',
        Properties: { ApiId: 'HttpApi', AuthorizerType: 'JWT', Name: 'jwt' },
      },
      RestApi: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'catch-all-rest-api' } },
      ProxyResource: {
        Type: 'AWS::ApiGateway::Resource',
        Properties: { RestApiId: 'RestApi', ParentId: 'RestApi', PathPart: '{proxy+}' },
      },
      ...catchAll,
    },
  } as unknown as Template;
}

function run(template: Template, logicalId: string) {
  const resource = (template.Resources as Record<string, Resource>)[logicalId]!;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 (CloudFormation) - catch-all route with valid authorization', () => {
  // Primary behavior owned by REQ-14: breadth of the matching pattern does not matter when
  // the route carries a valid authorization type (and an authorizer where required).
  it('passes a $default HTTP API route (any path, any method) using JWT with an associated authorizer', () => {
    const template = buildTemplate({
      CatchAllRoute: {
        Type: 'AWS::ApiGatewayV2::Route',
        Properties: {
          ApiId: 'HttpApi',
          RouteKey: '$default',
          AuthorizationType: 'JWT',
          AuthorizerId: 'JwtAuthorizer',
        },
      } as unknown as Resource,
    });

    expect(run(template, 'CatchAllRoute')).toBeNull();
  });

  it('passes an ANY method on a {proxy+} resource using AWS_IAM', () => {
    const template = buildTemplate({
      CatchAllMethod: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          RestApiId: 'RestApi',
          ResourceId: 'ProxyResource',
          HttpMethod: 'ANY',
          AuthorizationType: 'AWS_IAM',
        },
      } as unknown as Resource,
    });

    expect(run(template, 'CatchAllMethod')).toBeNull();
  });

  // Opposite outcome: identical catch-all route, but the authorization type is not a valid one.
  it('flags the same catch-all route when its authorization type is NONE', () => {
    const template = buildTemplate({
      CatchAllRoute: {
        Type: 'AWS::ApiGatewayV2::Route',
        Properties: {
          ApiId: 'HttpApi',
          RouteKey: '$default',
          AuthorizationType: 'NONE',
        },
      } as unknown as Resource,
    });

    const result = run(template, 'CatchAllRoute');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('CatchAllRoute');
  });
});
