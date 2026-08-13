import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004CfnAdapterFactory();

function scan(logicalId: string, resource: Resource) {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 (CloudFormation) — REQ-04: a non-OPTIONS method using IAM-based authorization passes', () => {
  it('does not flag a REST API method whose AuthorizationType is AWS_IAM', () => {
    const result = scan('GetItemMethod', {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        HttpMethod: 'GET',
        ResourceId: 'ApiResource',
        RestApiId: 'RestApi',
        AuthorizationType: 'AWS_IAM',
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });

  it('does not flag an HTTP API route whose AuthorizationType is AWS_IAM', () => {
    const result = scan('GetItemRoute', {
      Type: 'AWS::ApiGatewayV2::Route',
      Properties: {
        ApiId: 'HttpApi',
        RouteKey: 'GET /items',
        AuthorizationType: 'AWS_IAM',
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });

  // Opposite outcome: identical method, but the authorization mode present is not an
  // authenticated one — proves AWS_IAM (and not merely "some AuthorizationType") is what passes.
  // Primary behavior for the unauthenticated case is owned by the missing-authorization requirement.
  it('flags the same non-OPTIONS method when AuthorizationType is NONE', () => {
    const result = scan('GetItemMethod', {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        HttpMethod: 'GET',
        ResourceId: 'ApiResource',
        RestApiId: 'RestApi',
        AuthorizationType: 'NONE',
      },
    } as unknown as Resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('GetItemMethod');
  });
});
