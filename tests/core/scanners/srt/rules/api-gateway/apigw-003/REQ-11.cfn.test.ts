import { describe, it, expect } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STAGE_LOGICAL_ID = 'ProdStage';
const STAGE_ARN = 'arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod';

function buildTemplate(association: Record<string, unknown>): Template {
  return {
    Resources: {
      [STAGE_LOGICAL_ID]: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'abc123',
          StageName: 'prod',
          DeploymentId: 'dep1',
        },
      },
      StageWebAclAssociation: association,
    },
  } as unknown as Template;
}

function runControl(template: Template) {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[STAGE_LOGICAL_ID],
    logicalId: STAGE_LOGICAL_ID,
  };
  const adapter = new Apigw003CfnAdapterFactory().bind(context) as Apigw003Adapter;
  return { result: apigw003Control.run(adapter, context), adapter };
}

describe('APIGW-003 (CloudFormation) — legacy WAF Classic association only', () => {
  // Primary behavior owned by this requirement: WAF Classic (WAFRegional) is
  // end-of-life, so a stage covered only by a Classic association is unprotected.
  it('flags a stage associated only with a WAF Classic (WAFRegional) regional web ACL', () => {
    const template = buildTemplate({
      Type: 'AWS::WAFRegional::WebACLAssociation',
      Properties: {
        ResourceArn: STAGE_ARN,
        WebACLId: 'legacy-classic-web-acl-id',
      },
    });

    const { result, adapter } = runControl(template);

    expect(adapter.hasWebAclAssociation()).toBe(false);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe(STAGE_LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
  });

  // Opposite outcome: same stage, same target ARN — only the WAF generation changes.
  it('does not flag the same stage when the association is current-generation WAFv2', () => {
    const template = buildTemplate({
      Type: 'AWS::WAFv2::WebACLAssociation',
      Properties: {
        ResourceArn: STAGE_ARN,
        WebACLArn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/current/abcd',
      },
    });

    const { result, adapter } = runControl(template);

    expect(adapter.hasWebAclAssociation()).toBe(true);
    expect(result).toBeNull();
  });
});
