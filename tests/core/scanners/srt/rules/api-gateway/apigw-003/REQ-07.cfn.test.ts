import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STAGE_LOGICAL_ID = 'ProdStage';

/**
 * Builds a template with one API Gateway stage and one WAFv2 web ACL association
 * whose ResourceArn is whatever the caller supplies.
 */
function buildTemplate(resourceArn: unknown): Template {
  return {
    Resources: {
      MyApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: { Name: 'my-api' },
      },
      [STAGE_LOGICAL_ID]: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          // !Ref MyApi collapses to the logical id string after preprocessing
          RestApiId: 'MyApi',
          StageName: 'prod',
        },
      },
      StageWafAssociation: {
        Type: 'AWS::WAFv2::WebACLAssociation',
        Properties: {
          WebACLArn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/abcd1234',
          ResourceArn: resourceArn,
        },
      },
    },
  } as unknown as Template;
}

function bindStage(template: Template): { adapter: Apigw003Adapter; context: CfnContext } {
  const resources = (template.Resources ?? {}) as Record<string, unknown>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[STAGE_LOGICAL_ID] as CfnContext['resource'],
    logicalId: STAGE_LOGICAL_ID,
  };
  const adapter = new Apigw003CfnAdapterFactory().bind(context);
  return { adapter, context };
}

describe('APIGW-003 (CloudFormation) - unresolvable web ACL association target', () => {
  // Primary behaviour owned by this requirement: unresolvable coverage evidence passes.
  it('passes when the association ResourceArn is an unresolved Fn::If', () => {
    const template = buildTemplate({
      'Fn::If': [
        'IsProd',
        'arn:aws:apigateway:us-east-1::/restapis/MyApi/stages/prod',
        'arn:aws:apigateway:us-east-1::/restapis/MyApi/stages/dev',
      ],
    });
    const { adapter, context } = bindStage(template);

    expect(adapter.hasWebAclAssociation()).toBe(true);
    expect(apigw003Control.run(adapter, context)).toBeNull();
  });

  it('passes when the association ResourceArn is an unresolved Fn::ImportValue', () => {
    const template = buildTemplate({ 'Fn::ImportValue': 'SharedStageArn' });
    const { adapter, context } = bindStage(template);

    expect(adapter.hasWebAclAssociation()).toBe(true);
    expect(apigw003Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: the same association, but with a fully resolved target that
  // demonstrably designates a different stage, must be flagged.
  it('flags the stage when the ResourceArn resolves to a different stage', () => {
    const template = buildTemplate('arn:aws:apigateway:us-east-1::/restapis/OtherApi/stages/other');
    const { adapter, context } = bindStage(template);

    expect(adapter.hasWebAclAssociation()).toBe(false);
    const result = apigw003Control.run(adapter, context);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe(STAGE_LOGICAL_ID);
  });
});
