import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

// REQ-01 (primary): a non-OPTIONS API Gateway method/route with no authorization
// configuration of any kind must be flagged (publicly invokable).

const factory = new Apigw004CfnAdapterFactory();

function scan(logicalId: string, resources: Record<string, Resource>) {
  const template = { Resources: resources } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[logicalId]!,
    logicalId,
  };
  return apigw004Control.run(factory.bind(context), context);
}

describe('APIGW-004 REQ-01 (CloudFormation)', () => {
  it('flags an AWS::ApiGateway::Method with no authorization configuration', () => {
    const result = scan('GetMethod', {
      GetMethod: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'RestApi' },
        },
      } as unknown as Resource,
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('GetMethod');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
  });

  it('flags an AWS::ApiGatewayV2::Route with no authorization configuration', () => {
    const result = scan('HttpRoute', {
      HttpRoute: {
        Type: 'AWS::ApiGatewayV2::Route',
        Properties: {
          ApiId: { Ref: 'HttpApi' },
          RouteKey: 'POST /orders',
          Target: 'integrations/abc123',
        },
      } as unknown as Resource,
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('HttpRoute');
    expect(result?.resourceType).toBe('AWS::ApiGatewayV2::Route');
  });

  // Opposite outcome — nearest input that flips the verdict: the same method with
  // an accepted authorization type present. Owned by the "authorization type
  // configured" behavior of APIGW-004, included here to prove discrimination.
  it('does not flag an AWS::ApiGateway::Method whose AuthorizationType is AWS_IAM', () => {
    const result = scan('GetMethod', {
      GetMethod: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'RestApi' },
          AuthorizationType: 'AWS_IAM',
        },
      } as unknown as Resource,
    });

    expect(result).toBeNull();
  });

  it('does not flag an AWS::ApiGatewayV2::Route whose AuthorizationType is AWS_IAM', () => {
    const result = scan('HttpRoute', {
      HttpRoute: {
        Type: 'AWS::ApiGatewayV2::Route',
        Properties: {
          ApiId: { Ref: 'HttpApi' },
          RouteKey: 'POST /orders',
          Target: 'integrations/abc123',
          AuthorizationType: 'AWS_IAM',
        },
      } as unknown as Resource,
    });

    expect(result).toBeNull();
  });
});
