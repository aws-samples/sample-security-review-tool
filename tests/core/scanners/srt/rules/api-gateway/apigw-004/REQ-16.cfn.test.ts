import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004CfnAdapterFactory();

/**
 * Builds the HTTP API template with the given route properties.
 * Intrinsics are written pre-resolution and inlined here as the values the rule
 * actually sees after parseCfnTemplate (Ref to a logical ID -> logical ID string).
 */
function buildTemplate(routeProperties: Record<string, unknown>): Template {
  return {
    Resources: {
      HttpApi: {
        Type: 'AWS::ApiGatewayV2::Api',
        Properties: { Name: 'http-api', ProtocolType: 'HTTP' },
      },
      JwtAuthorizer: {
        Type: 'AWS::ApiGatewayV2::Authorizer',
        Properties: {
          // !Ref HttpApi -> "HttpApi"
          ApiId: 'HttpApi',
          AuthorizerType: 'JWT',
          IdentitySource: ['$request.header.Authorization'],
          Name: 'jwt-authorizer',
          JwtConfiguration: {
            Audience: ['my-client-id'],
            Issuer: 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example',
          },
        },
      },
      GetItemsRoute: {
        Type: 'AWS::ApiGatewayV2::Route',
        Properties: routeProperties,
      },
    },
  } as unknown as Template;
}

function run(template: Template): ScanResult | null {
  const resources = template.Resources as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['GetItemsRoute'],
    logicalId: 'GetItemsRoute',
  };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 (CloudFormation) - JWT authorization on a non-OPTIONS route', () => {
  // Primary behavior owned by this requirement: JWT + associated authorizer is
  // native token-based access control for HTTP APIs and must pass.
  it('passes a non-OPTIONS route using JWT authorization with an associated authorizer', () => {
    const result = run(
      buildTemplate({
        ApiId: 'HttpApi', // !Ref HttpApi
        RouteKey: 'GET /items',
        AuthorizationType: 'JWT',
        AuthorizerId: 'JwtAuthorizer', // !Ref JwtAuthorizer
        Target: 'integrations/GetItemsIntegration',
      }),
    );

    expect(result).toBeNull();
  });

  // Opposite outcome: same JWT authorization type, but no authorizer is attached,
  // so the route is not actually protected and must be flagged.
  it('flags a non-OPTIONS route declaring JWT authorization with no associated authorizer', () => {
    const result = run(
      buildTemplate({
        ApiId: 'HttpApi',
        RouteKey: 'GET /items',
        AuthorizationType: 'JWT',
        Target: 'integrations/GetItemsIntegration',
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('GetItemsRoute');
  });
});
