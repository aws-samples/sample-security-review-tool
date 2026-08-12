import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-08 (APIGW-003): Several web ACL associations exist targeting different stages,
 * and one of them targets the assessed stage -> PASS (the stage is protected).
 */

const ASSESSED_STAGE_ID = 'ProdStage';

const stageArn = (apiId: string, stageName: string): string =>
  `arn:aws:apigateway:us-east-1::/restapis/${apiId}/stages/${stageName}`;

function buildTemplate(coveringResourceArn: string): Template {
  return {
    Resources: {
      // Assessed stage: RestApiId / StageName already resolved to literals.
      [ASSESSED_STAGE_ID]: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'MyApi',
          StageName: 'prod',
          DeploymentId: 'MyDeployment',
        },
      },
      DevStage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'MyApi',
          StageName: 'dev',
          DeploymentId: 'MyDeployment',
        },
      },
      OtherApiStage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'OtherApi',
          StageName: 'prod',
          DeploymentId: 'OtherDeployment',
        },
      },
      // Several associations, each aimed at a different stage.
      DevStageAssociation: {
        Type: 'AWS::WAFv2::WebACLAssociation',
        Properties: {
          WebACLArn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/dev-acl/1111',
          ResourceArn: stageArn('MyApi', 'dev'),
        },
      },
      OtherApiAssociation: {
        Type: 'AWS::WAFv2::WebACLAssociation',
        Properties: {
          WebACLArn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/other-acl/2222',
          ResourceArn: stageArn('OtherApi', 'prod'),
        },
      },
      CoveringAssociation: {
        Type: 'AWS::WAFv2::WebACLAssociation',
        Properties: {
          WebACLArn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-acl/3333',
          ResourceArn: coveringResourceArn,
        },
      },
    },
  } as unknown as Template;
}

function bindAdapter(template: Template): { adapter: Apigw003Adapter; context: CfnContext } {
  const resources = template.Resources as Record<string, NonNullable<Template['Resources']>[string]>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[ASSESSED_STAGE_ID],
    logicalId: ASSESSED_STAGE_ID,
  };
  return { adapter: new Apigw003CfnAdapterFactory().bind(context), context };
}

describe('APIGW-003 REQ-08 (CloudFormation)', () => {
  it('passes when one of several associations targets the assessed stage', () => {
    const { adapter, context } = bindAdapter(buildTemplate(stageArn('MyApi', 'prod')));

    expect(adapter.hasWebAclAssociation()).toBe(true);
    expect(apigw003Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: every association targets some other stage, so no association
  // covers the assessed stage and the missing-association behavior (owned by APIGW-003)
  // must produce a finding.
  it('flags the stage when none of the several associations targets the assessed stage', () => {
    const { adapter, context } = bindAdapter(buildTemplate(stageArn('MyApi', 'staging')));

    expect(adapter.hasWebAclAssociation()).toBe(false);
    const result = apigw003Control.run(adapter, context);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe(ASSESSED_STAGE_ID);
  });
});
