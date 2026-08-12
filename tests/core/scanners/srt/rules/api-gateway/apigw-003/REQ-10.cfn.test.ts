import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STAGE_LOGICAL_ID = 'ProdStage';

/**
 * Builds a template with one REST API, one stage and one WAFv2 association whose
 * ResourceArn is a wildcard ("all stages") pattern scoped to `protectedApiId`.
 * Values are written as already-resolved literals, mirroring what the rule sees
 * after parseCfnTemplate turns `!Ref MyApi` into the logical ID string "MyApi".
 */
function buildTemplate(protectedApiId: string): Template {
  return {
    Resources: {
      MyApi: { Type: 'AWS::ApiGateway::RestApi', Properties: {} },
      OtherApi: { Type: 'AWS::ApiGateway::RestApi', Properties: {} },
      [STAGE_LOGICAL_ID]: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'MyApi',
          StageName: 'prod',
        },
      },
      StageWebAclAssociation: {
        Type: 'AWS::WAFv2::WebACLAssociation',
        Properties: {
          WebACLArn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/edge-acl/abc123',
          ResourceArn: `arn:aws:apigateway:us-east-1::/restapis/${protectedApiId}/stages/*`,
        },
      },
    },
  } as unknown as Template;
}

function runControl(template: Template): ScanResult | null {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[STAGE_LOGICAL_ID],
    logicalId: STAGE_LOGICAL_ID,
  };
  const adapter = new Apigw003CfnAdapterFactory().bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 (CloudFormation): wildcard web ACL association scoped to a different API', () => {
  // Primary behaviour owned by this requirement: a broad "all stages" pattern that
  // belongs to another REST API never protects the assessed stage, so flag it.
  it('flags the stage when the wildcard association targets another API', () => {
    const result = runControl(buildTemplate('OtherApi'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe(STAGE_LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
  });

  // Opposite outcome: the only thing changed is which API the wildcard is scoped
  // to. Scoped to the assessed stage's own API, the wildcard provably covers it.
  it('does not flag the stage when the same wildcard is scoped to the stage owning API', () => {
    const result = runControl(buildTemplate('MyApi'));

    expect(result).toBeNull();
  });
});
