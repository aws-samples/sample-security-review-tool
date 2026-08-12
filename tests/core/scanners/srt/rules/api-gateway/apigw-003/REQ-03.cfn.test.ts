import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * APIGW-003 — Public-facing API Gateway stages must have an AWS WAF web ACL associated.
 *
 * REQ-03: A web ACL association whose protected target is a stage of a DIFFERENT API
 * confers no protection on the assessed stage, so the assessed stage must be flagged.
 */

const factory = new Apigw003CfnAdapterFactory();

// Assessed stage: stage "prod" of REST API logical id "AssessedApi".
// (`RestApiId: !Ref AssessedApi` resolves to the logical id string "AssessedApi".)
const assessedStage: Resource = {
  Type: 'AWS::ApiGateway::Stage',
  Properties: {
    RestApiId: 'AssessedApi',
    StageName: 'prod',
    DeploymentId: 'AssessedDeployment',
  },
} as unknown as Resource;

function buildTemplate(association: Resource): Template {
  return {
    Resources: {
      AssessedApi: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'assessed-api' } },
      OtherApi: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'other-api' } },
      WebAcl: { Type: 'AWS::WAFv2::WebACL', Properties: { Name: 'shared-acl', Scope: 'REGIONAL' } },
      AssessedStage: assessedStage,
      Association: association,
    },
  } as unknown as Template;
}

function run(template: Template) {
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, Resource>)['AssessedStage'],
    logicalId: 'AssessedStage',
  };
  return apigw003Control.run(factory.bind(context), context);
}

describe('APIGW-003 REQ-03 (CloudFormation): association protecting a stage of another API', () => {
  it('flags the assessed stage when the association ARN names the same stage name under a different API', () => {
    const association: Resource = {
      Type: 'AWS::WAFv2::WebACLAssociation',
      Properties: {
        WebACLArn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/shared-acl/abcd',
        // Protects stage "prod" of OtherApi, not of AssessedApi.
        ResourceArn: 'arn:aws:apigateway:us-east-1::/restapis/OtherApi/stages/prod',
      },
    } as unknown as Resource;

    const result = run(buildTemplate(association));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe('AssessedStage');
  });

  it('flags the assessed stage when the association targets another stage resource by reference', () => {
    const template = buildTemplate({
      Type: 'AWS::WAFv2::WebACLAssociation',
      Properties: {
        WebACLArn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/shared-acl/abcd',
        // `!Ref OtherStage` resolves to the logical id string of the other API's stage.
        ResourceArn: 'OtherStage',
      },
    } as unknown as Resource);
    (template.Resources as Record<string, Resource>)['OtherStage'] = {
      Type: 'AWS::ApiGateway::Stage',
      Properties: { RestApiId: 'OtherApi', StageName: 'prod', DeploymentId: 'OtherDeployment' },
    } as unknown as Resource;

    const result = run(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });

  // Opposite outcome — the association names the ASSESSED stage's API, so it protects
  // this stage and no finding is produced. Owned by the passing-case requirement; included
  // here so the file cannot be satisfied by a control that flags everything.
  it('does not flag when the association ARN names the assessed stage of the assessed API', () => {
    const association: Resource = {
      Type: 'AWS::WAFv2::WebACLAssociation',
      Properties: {
        WebACLArn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/shared-acl/abcd',
        ResourceArn: 'arn:aws:apigateway:us-east-1::/restapis/AssessedApi/stages/prod',
      },
    } as unknown as Resource;

    const result = run(buildTemplate(association));

    expect(result).toBeNull();
  });
});
