import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STAGE_LOGICAL_ID = 'ProdStage';

/**
 * Builds a template (already in post-`parseCfnTemplate` form) containing a single
 * API Gateway stage plus one WAFv2 web ACL association whose ResourceArn is supplied
 * by the caller.
 */
function buildTemplate(resourceArn: unknown): Template {
  return {
    Resources: {
      [STAGE_LOGICAL_ID]: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'MyApi',
          StageName: 'prod',
          DeploymentId: 'MyDeployment',
        },
      },
      StageWebAclAssociation: {
        Type: 'AWS::WAFv2::WebACLAssociation',
        Properties: {
          WebACLArn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/api-acl/abc123',
          ResourceArn: resourceArn,
        },
      },
    },
  } as unknown as Template;
}

function runControl(template: Template) {
  const resources = template.Resources as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[STAGE_LOGICAL_ID],
    logicalId: STAGE_LOGICAL_ID,
  };
  const adapter = new Apigw003CfnAdapterFactory().bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 [CloudFormation] REQ-06: web ACL association with an empty protected-target value', () => {
  // Primary behavior owned by this requirement: an association whose ResourceArn is
  // present but empty provides no evidence that THIS stage is protected -> flag.
  it('flags the stage when the association ResourceArn is an empty string', () => {
    const result = runControl(buildTemplate(''));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe(STAGE_LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
  });

  it('flags the stage when the association ResourceArn is whitespace only', () => {
    const result = runControl(buildTemplate('   '));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });

  // Opposite outcome (nearest input that flips the verdict): identical template, but the
  // association's ResourceArn actually identifies this stage -> protection is evidenced.
  it('does not flag the stage when the same association carries a ResourceArn identifying this stage', () => {
    const result = runControl(buildTemplate('arn:aws:apigateway:us-east-1::/restapis/MyApi/stages/prod'));

    expect(result).toBeNull();
  });
});
