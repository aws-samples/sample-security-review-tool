import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004CfnAdapterFactory();

function run(logicalId: string, resources: Record<string, Resource>) {
  const template = { Resources: resources } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[logicalId] as Resource,
    logicalId,
  };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

describe('APIGW-004 (CloudFormation): API keys are not authorization', () => {
  // REQ-15 owns this behavior: a non-OPTIONS method with no authorization type must be
  // flagged even when ApiKeyRequired is true, because API keys are for usage plans /
  // throttling / metering, not authentication or authorization.
  it('flags a non-OPTIONS REST method that has no AuthorizationType but requires an API key', () => {
    const result = run('GetItemsMethod', {
      RestApi: { Type: 'AWS::ApiGateway::RestApi', Properties: {} } as unknown as Resource,
      GetItemsMethod: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          // reference form: !Ref RestApi collapses to the logical id string
          RestApiId: 'RestApi',
          ApiKeyRequired: true,
        },
      } as unknown as Resource,
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('GetItemsMethod');
  });

  it('flags a non-OPTIONS REST method with AuthorizationType NONE that requires an API key', () => {
    const result = run('PostItemsMethod', {
      RestApi: { Type: 'AWS::ApiGateway::RestApi', Properties: {} } as unknown as Resource,
      PostItemsMethod: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'POST',
          RestApiId: 'RestApi',
          AuthorizationType: 'NONE',
          ApiKeyRequired: true,
        },
      } as unknown as Resource,
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
  });

  it('flags a non-OPTIONS HTTP API route with AuthorizationType NONE that requires an API key', () => {
    const result = run('GetItemsRoute', {
      HttpApi: { Type: 'AWS::ApiGatewayV2::Api', Properties: {} } as unknown as Resource,
      GetItemsRoute: {
        Type: 'AWS::ApiGatewayV2::Route',
        Properties: {
          ApiId: 'HttpApi',
          RouteKey: 'GET /items',
          AuthorizationType: 'NONE',
          ApiKeyRequired: true,
        },
      } as unknown as Resource,
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
  });

  // Opposite outcome: identical fixture except the authorization type meets the standard.
  it('does not flag the same API-key-required method when AWS_IAM authorization is configured', () => {
    const result = run('GetItemsMethod', {
      RestApi: { Type: 'AWS::ApiGateway::RestApi', Properties: {} } as unknown as Resource,
      GetItemsMethod: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          RestApiId: 'RestApi',
          AuthorizationType: 'AWS_IAM',
          ApiKeyRequired: true,
        },
      } as unknown as Resource,
    });

    expect(result).toBeNull();
  });
});
