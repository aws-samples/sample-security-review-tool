import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004CfnAdapterFactory();

function scan(logicalId: string, resource: Resource): ScanResult | null {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 (CloudFormation) — user-pool-based authorization without an associated authorizer', () => {
  // Primary behavior owned by REQ-08: COGNITO_USER_POOLS / JWT authorization must be
  // backed by an associated authorizer, otherwise no token validation occurs.
  it('flags a non-OPTIONS REST method with COGNITO_USER_POOLS authorization and no AuthorizerId', () => {
    const result = scan('GetItemsMethod', {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        HttpMethod: 'GET',
        ResourceId: 'ItemsResource',
        RestApiId: 'RestApi',
        AuthorizationType: 'COGNITO_USER_POOLS',
      },
    } as unknown as Resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('GetItemsMethod');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
  });

  it('flags a non-OPTIONS HTTP API route with JWT (user pool) authorization and no AuthorizerId', () => {
    const result = scan('GetItemsRoute', {
      Type: 'AWS::ApiGatewayV2::Route',
      Properties: {
        ApiId: 'HttpApi',
        RouteKey: 'GET /items',
        AuthorizationType: 'JWT',
      },
    } as unknown as Resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('GetItemsRoute');
  });

  // Opposite outcome: identical method, but the user-pool authorization IS backed by an
  // associated authorizer (AuthorizerId present) — must not be flagged.
  it('does not flag the same method when an authorizer is associated with it', () => {
    const result = scan('GetItemsMethod', {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        HttpMethod: 'GET',
        ResourceId: 'ItemsResource',
        RestApiId: 'RestApi',
        AuthorizationType: 'COGNITO_USER_POOLS',
        AuthorizerId: 'UserPoolAuthorizer',
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });
});
