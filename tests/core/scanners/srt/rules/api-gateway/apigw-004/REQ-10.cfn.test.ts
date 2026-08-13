import { describe, it, expect } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (APIGW-004): An authorization type value that is present but EMPTY is not one of the
 * accepted values (AWS_IAM, COGNITO_USER_POOLS, CUSTOM) and therefore must be flagged.
 */

const factory = new Apigw004CfnAdapterFactory();

function scan(logicalId: string, resources: Record<string, Resource>) {
  const template = { Resources: resources } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[logicalId]!,
    logicalId,
  };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

function restMethod(authorizationType: string): Record<string, Resource> {
  return {
    RestApi: { Type: 'AWS::ApiGateway::RestApi', Properties: {} } as unknown as Resource,
    GetMethod: {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        RestApiId: { Ref: 'RestApi' },
        ResourceId: { Ref: 'RestApi' },
        HttpMethod: 'GET',
        AuthorizationType: authorizationType,
      },
    } as unknown as Resource,
  };
}

function httpRoute(authorizationType: string): Record<string, Resource> {
  return {
    HttpApi: { Type: 'AWS::ApiGatewayV2::Api', Properties: {} } as unknown as Resource,
    GetRoute: {
      Type: 'AWS::ApiGatewayV2::Route',
      Properties: {
        ApiId: 'HttpApi',
        RouteKey: 'GET /items',
        AuthorizationType: authorizationType,
      },
    } as unknown as Resource,
  };
}

describe('APIGW-004 REQ-10 (CloudFormation): empty authorization type', () => {
  it('flags an AWS::ApiGateway::Method whose AuthorizationType is an empty string', () => {
    const result = scan('GetMethod', restMethod(''));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('GetMethod');
  });

  it('flags an AWS::ApiGatewayV2::Route whose AuthorizationType is an empty string', () => {
    const result = scan('GetRoute', httpRoute(''));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('GetRoute');
  });

  // Opposite outcome: identical fixture except the authorization type is a real accepted value.
  it('does not flag the same method when AuthorizationType is the accepted value AWS_IAM', () => {
    expect(scan('GetMethod', restMethod('AWS_IAM'))).toBeNull();
  });

  // Opposite outcome for the V2 route family.
  it('does not flag the same route when AuthorizationType is the accepted value AWS_IAM', () => {
    expect(scan('GetRoute', httpRoute('AWS_IAM'))).toBeNull();
  });
});
