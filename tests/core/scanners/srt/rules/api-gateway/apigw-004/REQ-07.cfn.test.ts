import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004CfnAdapterFactory();

/**
 * Builds a template that contains a Cognito user pool authorizer plus the method/route
 * under test. Values are written as they appear AFTER parseCfnTemplate preprocessing,
 * i.e. `!Ref ApiAuthorizer` has already collapsed to the logical id string.
 */
function buildTemplate(logicalId: string, resource: Resource): Template {
  return {
    Resources: {
      ApiAuthorizer: {
        Type: 'AWS::ApiGateway::Authorizer',
        Properties: {
          Name: 'user-pool-authorizer',
          RestApiId: 'RestApi',
          Type: 'COGNITO_USER_POOLS',
          IdentitySource: 'method.request.header.Authorization',
          ProviderARNs: ['arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_abc123'],
        },
      },
      [logicalId]: resource,
    },
  } as unknown as Template;
}

function run(logicalId: string, resource: Resource) {
  const template = buildTemplate(logicalId, resource);
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 (CloudFormation) — non-OPTIONS method with user-pool authorization and an associated authorizer', () => {
  // Primary behavior owned by this requirement: COGNITO_USER_POOLS + authorizer => pass.
  it('passes a REST API method using COGNITO_USER_POOLS with an authorizer defined for the same API', () => {
    const result = run('GetItemsMethod', {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        RestApiId: 'RestApi',
        ResourceId: 'ApiResource',
        HttpMethod: 'GET',
        AuthorizationType: 'COGNITO_USER_POOLS',
        // !Ref ApiAuthorizer resolves to the logical id string
        AuthorizerId: 'ApiAuthorizer',
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });

  it('passes an HTTP API route using JWT (user pool) authorization with an associated authorizer', () => {
    const result = run('GetItemsRoute', {
      Type: 'AWS::ApiGatewayV2::Route',
      Properties: {
        ApiId: 'HttpApi',
        RouteKey: 'GET /items',
        AuthorizationType: 'JWT',
        AuthorizerId: 'ApiAuthorizer',
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });

  // Opposite outcome: authorization value present but not a user-pool/IAM/custom mode.
  it('flags the same method when the authorization type is NONE instead of COGNITO_USER_POOLS', () => {
    const result = run('GetItemsMethod', {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        RestApiId: 'RestApi',
        ResourceId: 'ApiResource',
        HttpMethod: 'GET',
        AuthorizationType: 'NONE',
        AuthorizerId: 'ApiAuthorizer',
      },
    } as unknown as Resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('GetItemsMethod');
  });

  // Opposite outcome: user-pool mode declared but no authorizer associated with the method.
  it('flags a COGNITO_USER_POOLS method whose authorizer association is empty', () => {
    const result = run('GetItemsMethod', {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        RestApiId: 'RestApi',
        ResourceId: 'ApiResource',
        HttpMethod: 'GET',
        AuthorizationType: 'COGNITO_USER_POOLS',
        AuthorizerId: '',
      },
    } as unknown as Resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
  });
});
