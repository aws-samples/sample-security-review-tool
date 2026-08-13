import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (APIGW-004): A non-OPTIONS method declares an authorizer-requiring authorization
 * type, but the identity of the associated authorizer cannot be resolved at analysis time.
 * Expected behavior: pass — an authorizer association is present, and the rule cannot prove
 * that no valid authorizer covers the method, so it must not flag.
 *
 * Fixtures below are written as the rule sees them AFTER template preprocessing:
 * Fn::ImportValue is left intact as an opaque object; Refs to resources collapse to logical IDs.
 */

const factory = new Apigw004CfnAdapterFactory();

function run(template: Template, logicalId: string) {
  const resource = (template.Resources as Record<string, Resource>)[logicalId]!;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  return apigw004Control.run(factory.bind(context) as never, context);
}

describe('APIGW-004 REQ-12 (CloudFormation): unresolvable authorizer association passes', () => {
  it('does not flag a REST method with CUSTOM authorization whose AuthorizerId is an unresolved cross-stack import', () => {
    const template: Template = {
      Resources: {
        RestApi: { Type: 'AWS::ApiGateway::RestApi', Properties: {} },
        PostMethod: {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            RestApiId: 'RestApi',
            HttpMethod: 'POST',
            AuthorizationType: 'CUSTOM',
            AuthorizerId: { 'Fn::ImportValue': 'SharedAuthorizerId' },
          },
        },
      },
    } as unknown as Template;

    expect(run(template, 'PostMethod')).toBeNull();
  });

  it('does not flag an HTTP API route with JWT authorization whose AuthorizerId names an authorizer defined outside this template', () => {
    const template: Template = {
      Resources: {
        HttpApi: { Type: 'AWS::ApiGatewayV2::Api', Properties: {} },
        GetItemsRoute: {
          Type: 'AWS::ApiGatewayV2::Route',
          Properties: {
            ApiId: 'HttpApi',
            RouteKey: 'GET /items',
            AuthorizationType: 'JWT',
            AuthorizerId: 'ImportedJwtAuthorizer',
          },
        },
      },
    } as unknown as Template;

    expect(run(template, 'GetItemsRoute')).toBeNull();
  });

  // Opposite outcome: the authorizer association IS resolvable and provably belongs to a
  // different REST API, so no valid authorizer covers this method (primary behavior of the
  // "authorizer-backed type without a covering authorizer" requirement).
  it('flags a REST method with CUSTOM authorization whose resolvable authorizer belongs to a different API', () => {
    const template: Template = {
      Resources: {
        RestApi: { Type: 'AWS::ApiGateway::RestApi', Properties: {} },
        OtherRestApi: { Type: 'AWS::ApiGateway::RestApi', Properties: {} },
        OtherApiAuthorizer: {
          Type: 'AWS::ApiGateway::Authorizer',
          Properties: { RestApiId: 'OtherRestApi', Type: 'TOKEN', Name: 'other' },
        },
        PostMethod: {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            RestApiId: 'RestApi',
            HttpMethod: 'POST',
            AuthorizationType: 'CUSTOM',
            AuthorizerId: 'OtherApiAuthorizer',
          },
        },
      },
    } as unknown as Template;

    const result = run(template, 'PostMethod');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('PostMethod');
  });
});
