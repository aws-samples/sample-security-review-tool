import { describe, expect, it } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-17 (APIGW-004): A non-OPTIONS method with no authorization type must be flagged even when the
 * parent API carries a resource policy. A resource policy only restricts origin/account and is an
 * optional control used alongside — not instead of — an authorizer.
 */

const RESOURCE_POLICY = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Principal: '*',
      Action: 'execute-api:Invoke',
      Resource: 'execute-api:/*',
      Condition: { IpAddress: { 'aws:SourceIp': ['192.0.2.0/24'] } },
    },
  ],
};

function buildTemplate(methodProperties: Record<string, unknown>): Template {
  return {
    Resources: {
      RestApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'policy-protected-api',
          Policy: RESOURCE_POLICY,
        },
      },
      ApiResource: {
        Type: 'AWS::ApiGateway::Resource',
        Properties: { RestApiId: 'RestApi', PathPart: 'items', ParentId: 'RestApi' },
      },
      Method: {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          RestApiId: 'RestApi',
          ResourceId: 'ApiResource',
          ...methodProperties,
        },
      },
    },
  } as unknown as Template;
}

function runControl(template: Template, logicalId: string) {
  const resources = (template.Resources ?? {}) as Record<string, Resource>;
  const resource = resources[logicalId]!;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const factory = new Apigw004CfnAdapterFactory();
  expect(factory.appliesTo(resource.Type)).toBe(true);
  return apigw004Control.run(factory.bind(context), context);
}

describe('APIGW-004 REQ-17 (CloudFormation): API-level resource policy does not substitute for method authorization', () => {
  it('flags a non-OPTIONS method with no authorization type even though the API has a restrictive resource policy', () => {
    const result = runControl(buildTemplate({ HttpMethod: 'GET' }), 'Method');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
    expect(result?.resourceName).toBe('Method');
  });

  // Opposite outcome: the requirement turns on the method's authorization type, so the nearest
  // input that flips the verdict is the same policy-protected API with AWS_IAM authorization set.
  it('does not flag when the same policy-protected API method configures AWS_IAM authorization', () => {
    const result = runControl(buildTemplate({ HttpMethod: 'GET', AuthorizationType: 'AWS_IAM' }), 'Method');

    expect(result).toBeNull();
  });
});
