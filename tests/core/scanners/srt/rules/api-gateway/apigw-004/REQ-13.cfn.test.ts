import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { Apigw004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (APIGW-004): Rules evaluate one resource at a time. When an API contains several
 * non-OPTIONS methods and some of the siblings are unauthenticated, the method being assessed
 * must still pass so long as it has a valid authorization type (with any required authorizer).
 * Findings for the unauthenticated siblings are raised when those resources are assessed.
 */

const factory = new Apigw004CfnAdapterFactory();

function assess(template: Template, logicalId: string): ScanResult | null {
  const resource = (template.Resources ?? {})[logicalId] as Resource;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = factory.bind(context) as Apigw004Adapter;
  return apigw004Control.run(adapter, context);
}

/**
 * REST API with three non-OPTIONS methods:
 *  - GetItems (assessed): COGNITO_USER_POOLS with an authorizer wired to the same API
 *  - PostItems / PutItems (siblings): unauthenticated
 */
function restApiTemplate(assessedAuthorizationType: string): Template {
  return {
    Resources: {
      RestApi: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'items-api' } },
      MethodAuthorizer: {
        Type: 'AWS::ApiGateway::Authorizer',
        Properties: { Name: 'pool-authorizer', Type: 'COGNITO_USER_POOLS', RestApiId: 'RestApi' },
      },
      GetItems: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          RestApiId: 'RestApi',
          ResourceId: 'ItemsResource',
          AuthorizationType: assessedAuthorizationType,
          AuthorizerId: 'MethodAuthorizer',
        },
      },
      PostItems: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'POST',
          RestApiId: 'RestApi',
          ResourceId: 'ItemsResource',
          AuthorizationType: 'NONE',
        },
      },
      PutItems: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'PUT',
          RestApiId: 'RestApi',
          ResourceId: 'ItemsResource',
          AuthorizationType: 'NONE',
        },
      },
    },
  } as unknown as Template;
}

/**
 * HTTP API with three non-OPTIONS routes:
 *  - GetRoute (assessed): AWS_IAM
 *  - PostRoute / DeleteRoute (siblings): NONE
 */
function httpApiTemplate(assessedAuthorizationType: string): Template {
  return {
    Resources: {
      HttpApi: { Type: 'AWS::ApiGatewayV2::Api', Properties: { Name: 'items-http-api', ProtocolType: 'HTTP' } },
      GetRoute: {
        Type: 'AWS::ApiGatewayV2::Route',
        Properties: { ApiId: 'HttpApi', RouteKey: 'GET /items', AuthorizationType: assessedAuthorizationType },
      },
      PostRoute: {
        Type: 'AWS::ApiGatewayV2::Route',
        Properties: { ApiId: 'HttpApi', RouteKey: 'POST /items', AuthorizationType: 'NONE' },
      },
      DeleteRoute: {
        Type: 'AWS::ApiGatewayV2::Route',
        Properties: { ApiId: 'HttpApi', RouteKey: 'DELETE /items/{id}', AuthorizationType: 'NONE' },
      },
    },
  } as unknown as Template;
}

describe('APIGW-004 REQ-13 (CloudFormation): assessed method is authorized while siblings are not', () => {
  it('passes the assessed REST method with COGNITO_USER_POOLS and an associated authorizer, despite unauthenticated siblings', () => {
    expect(assess(restApiTemplate('COGNITO_USER_POOLS'), 'GetItems')).toBeNull();
  });

  it('passes the assessed HTTP API route with AWS_IAM, despite unauthenticated sibling routes', () => {
    expect(assess(httpApiTemplate('AWS_IAM'), 'GetRoute')).toBeNull();
  });

  // Opposite outcome: only the assessed method's authorization type changes to an
  // unauthorized value. Primary behavior for unauthenticated methods is owned by the
  // "missing authorization" requirement; asserted here so this file discriminates.
  it('flags the assessed REST method when its own authorization type is NONE (siblings unchanged)', () => {
    const result = assess(restApiTemplate('NONE'), 'GetItems');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('GetItems');
  });

  it('flags the assessed HTTP API route when its own authorization type is NONE (siblings unchanged)', () => {
    const result = assess(httpApiTemplate('NONE'), 'GetRoute');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('GetRoute');
  });
});
