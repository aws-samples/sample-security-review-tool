import { describe, it, expect } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw003CfnAdapterFactory();

function buildContext(template: Template, logicalId: string): CfnContext {
  const resource = (template.Resources as Record<string, any>)[logicalId];
  return { stackName: 'test-stack', template, resource, logicalId };
}

function run(template: Template, logicalId: string) {
  const context = buildContext(template, logicalId);
  const adapter = factory.bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

// Stage with no WAF association of any kind anywhere in the template.
const templateWithoutWaf: Template = {
  Resources: {
    Api: {
      Type: 'AWS::ApiGateway::RestApi',
      Properties: { Name: 'public-api' },
    },
    Deployment: {
      Type: 'AWS::ApiGateway::Deployment',
      Properties: { RestApiId: { Ref: 'Api' } },
    },
    ApiStage: {
      Type: 'AWS::ApiGateway::Stage',
      Properties: {
        StageName: 'prod',
        RestApiId: { Ref: 'Api' },
        DeploymentId: { Ref: 'Deployment' },
      },
    },
  },
} as unknown as Template;

// Identical template, except a WAFv2 web ACL association targeting the stage is present.
const templateWithWaf: Template = {
  Resources: {
    Api: {
      Type: 'AWS::ApiGateway::RestApi',
      Properties: { Name: 'public-api' },
    },
    Deployment: {
      Type: 'AWS::ApiGateway::Deployment',
      Properties: { RestApiId: { Ref: 'Api' } },
    },
    ApiStage: {
      Type: 'AWS::ApiGateway::Stage',
      Properties: {
        StageName: 'prod',
        RestApiId: { Ref: 'Api' },
        DeploymentId: { Ref: 'Deployment' },
      },
    },
    WebAcl: {
      Type: 'AWS::WAFv2::WebACL',
      Properties: { Name: 'api-acl', Scope: 'REGIONAL' },
    },
    WebAclAssociation: {
      Type: 'AWS::WAFv2::WebACLAssociation',
      Properties: {
        // !Ref ApiStage resolves to the logical id string "ApiStage"
        ResourceArn: 'ApiStage',
        WebACLArn: 'WebAcl',
      },
    },
  },
} as unknown as Template;

describe('APIGW-003 REQ-01 (CloudFormation): stage with no web ACL association anywhere in the template', () => {
  it('flags an API Gateway stage when the template contains no web application firewall association of any kind', () => {
    const result = run(templateWithoutWaf, 'ApiStage');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe('ApiStage');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
  });

  // Opposite outcome: nearest input that flips the verdict — the same stage, but a
  // web ACL association for it exists in the template. Primary behavior for the
  // "association present" case is owned by the associated-stage requirement.
  it('does not flag the same stage when a WAFv2 web ACL association targeting it is present', () => {
    const result = run(templateWithWaf, 'ApiStage');

    expect(result).toBeNull();
  });
});
