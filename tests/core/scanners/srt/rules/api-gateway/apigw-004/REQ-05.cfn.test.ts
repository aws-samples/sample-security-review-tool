import { describe, expect, it } from 'vitest';

import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (APIGW-004): A non-OPTIONS method that uses a CUSTOM (Lambda) authorization
 * type AND references an authorizer defined for the same API is compliant.
 *
 * Fixtures are written as they appear AFTER parseCfnTemplate: `!Ref MyAuthorizer`
 * has already collapsed to the logical id string "MyAuthorizer".
 */

const factory = new Apigw004CfnAdapterFactory();

const REST_API: Resource = {
  Type: 'AWS::ApiGateway::RestApi',
  Properties: { Name: 'orders-api' },
} as unknown as Resource;

const LAMBDA_AUTHORIZER: Resource = {
  Type: 'AWS::ApiGateway::Authorizer',
  Properties: {
    Name: 'orders-lambda-authorizer',
    Type: 'TOKEN',
    RestApiId: 'RestApi', // !Ref RestApi -> logical id
    AuthorizerUri: 'arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/AuthFn/invocations',
  },
} as unknown as Resource;

function buildContext(logicalId: string, resource: Resource): CfnContext {
  const template = {
    Resources: {
      RestApi: REST_API,
      HttpApi: {
        Type: 'AWS::ApiGatewayV2::Api',
        Properties: { Name: 'orders-http-api', ProtocolType: 'HTTP' },
      } as unknown as Resource,
      MyAuthorizer: LAMBDA_AUTHORIZER,
      HttpAuthorizer: {
        Type: 'AWS::ApiGatewayV2::Authorizer',
        Properties: { Name: 'http-lambda-authorizer', ApiId: 'HttpApi', AuthorizerType: 'REQUEST' },
      } as unknown as Resource,
      [logicalId]: resource,
    },
  } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId };
}

function run(logicalId: string, resource: Resource) {
  const context = buildContext(logicalId, resource);
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 REQ-05 (CloudFormation): CUSTOM authorization with an authorizer on the same API', () => {
  it('passes a non-OPTIONS REST method with AuthorizationType CUSTOM and an authorizer for the same API', () => {
    const method = {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        HttpMethod: 'GET',
        RestApiId: 'RestApi',
        ResourceId: 'OrdersResource',
        AuthorizationType: 'CUSTOM',
        AuthorizerId: 'MyAuthorizer',
      },
    } as unknown as Resource;

    expect(run('GetOrdersMethod', method)).toBeNull();
  });

  it('passes a non-OPTIONS HTTP API route with CUSTOM authorization and an authorizer for the same API', () => {
    const route = {
      Type: 'AWS::ApiGatewayV2::Route',
      Properties: {
        ApiId: 'HttpApi',
        RouteKey: 'GET /orders',
        AuthorizationType: 'CUSTOM',
        AuthorizerId: 'HttpAuthorizer',
      },
    } as unknown as Resource;

    expect(run('GetOrdersRoute', route)).toBeNull();
  });

  // Opposite outcome: authorization type present but not an accepted mode.
  // Primary behavior for the NONE/unauthenticated case belongs to the
  // missing-authorization requirement; asserted here only to prove this file
  // discriminates on the authorization type rather than always passing.
  it('flags an otherwise identical method whose authorization type is NONE', () => {
    const method = {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        HttpMethod: 'GET',
        RestApiId: 'RestApi',
        ResourceId: 'OrdersResource',
        AuthorizationType: 'NONE',
        AuthorizerId: 'MyAuthorizer',
      },
    } as unknown as Resource;

    const result = run('GetOrdersMethod', method);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
  });
});
