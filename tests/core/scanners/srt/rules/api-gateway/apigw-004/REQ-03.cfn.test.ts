import { describe, it, expect } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004CfnAdapterFactory();

function scan(logicalId: string, resource: Resource) {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  return apigw004Control.run(factory.bind(context), context);
}

describe('APIGW-004 REQ-03 (CloudFormation): OPTIONS methods are excluded from the authorization requirement', () => {
  it('passes an OPTIONS method with no authorization configured at all', () => {
    const result = scan('OptionsMethod', {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        RestApiId: { Ref: 'RestApi' },
        ResourceId: { Ref: 'ApiResource' },
        HttpMethod: 'OPTIONS',
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });

  it('passes an OPTIONS method that explicitly declares AuthorizationType NONE', () => {
    const result = scan('OptionsMethodNone', {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        RestApiId: { Ref: 'RestApi' },
        ResourceId: { Ref: 'ApiResource' },
        HttpMethod: 'OPTIONS',
        AuthorizationType: 'NONE',
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });

  it('passes an HTTP API OPTIONS route that explicitly declares AuthorizationType NONE', () => {
    const result = scan('OptionsRoute', {
      Type: 'AWS::ApiGatewayV2::Route',
      Properties: {
        ApiId: { Ref: 'HttpApi' },
        RouteKey: 'OPTIONS /items',
        AuthorizationType: 'NONE',
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });

  // Opposite outcome: the primary "missing authorization" behavior is owned by the
  // main APIGW-004 requirement. Only the verb changes here (OPTIONS -> POST), which
  // is what this scenario's exclusion turns on.
  it('flags an otherwise identical POST method with AuthorizationType NONE', () => {
    const result = scan('PostMethodNone', {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        RestApiId: { Ref: 'RestApi' },
        ResourceId: { Ref: 'ApiResource' },
        HttpMethod: 'POST',
        AuthorizationType: 'NONE',
      },
    } as unknown as Resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceName).toBe('PostMethodNone');
  });
});
