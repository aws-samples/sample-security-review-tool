import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004CfnAdapterFactory();

function buildContext(logicalId: string, resource: Resource, template?: Template): CfnContext {
  const resources = { [logicalId]: resource, ...(template?.Resources ?? {}) };
  return {
    stackName: 'test-stack',
    template: { ...(template ?? {}), Resources: resources } as Template,
    resource,
    logicalId,
  };
}

function run(context: CfnContext): ScanResult | null {
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 (CloudFormation) — CUSTOM authorization must be backed by an associated authorizer', () => {
  // Primary behavior owned by this requirement: CUSTOM type without an authorizer must be flagged.
  it('flags a non-OPTIONS method declaring CUSTOM authorization with no authorizer associated', () => {
    const context = buildContext('GetMethod', {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        HttpMethod: 'GET',
        ResourceId: 'ApiResource',
        RestApiId: 'RestApi',
        AuthorizationType: 'CUSTOM',
      },
    } as unknown as Resource);

    const result = run(context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('GetMethod');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
  });

  it('flags an ApiGatewayV2 route declaring CUSTOM authorization with no authorizer associated', () => {
    const context = buildContext('PostRoute', {
      Type: 'AWS::ApiGatewayV2::Route',
      Properties: {
        ApiId: 'HttpApi',
        RouteKey: 'POST /items',
        AuthorizationType: 'CUSTOM',
      },
    } as unknown as Resource);

    const result = run(context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('PostRoute');
  });

  // Opposite outcome: identical method, but the CUSTOM authorization type is backed by an authorizer.
  it('does not flag the same method when a custom authorizer is associated via AuthorizerId', () => {
    const context = buildContext(
      'GetMethod',
      {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          ResourceId: 'ApiResource',
          RestApiId: 'RestApi',
          AuthorizationType: 'CUSTOM',
          // !Ref LambdaAuthorizer resolves to the logical ID string after preprocessing
          AuthorizerId: 'LambdaAuthorizer',
        },
      } as unknown as Resource,
      {
        Resources: {
          LambdaAuthorizer: {
            Type: 'AWS::ApiGateway::Authorizer',
            Properties: { Type: 'TOKEN', Name: 'lambda-auth', RestApiId: 'RestApi' },
          },
        },
      } as unknown as Template,
    );

    const result = run(context);

    expect(result).toBeNull();
  });
});
