import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STAGE_LOGICAL_ID = 'ProdStage';
const STAGE_ARN = 'arn:aws:apigateway:us-east-1::/restapis/MyApi/stages/prod';

/**
 * Builds a template whose only variable is the web ACL identifier carried by an
 * association that already targets the assessed stage.
 */
function buildTemplate(webAcl: unknown, key: 'WebACLArn' | 'WebACLId' = 'WebACLArn'): Template {
  return {
    Resources: {
      MyApi: { Type: 'AWS::ApiGateway::RestApi', Properties: {} },
      [STAGE_LOGICAL_ID]: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          // !Ref MyApi resolves to the logical ID string after preprocessing
          RestApiId: 'MyApi',
          StageName: 'prod',
        },
      },
      StageWafAssociation: {
        Type: 'AWS::WAFv2::WebACLAssociation',
        Properties: {
          ResourceArn: STAGE_ARN,
          [key]: webAcl,
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template) {
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

describe('APIGW-003 CloudFormation - association present but web ACL reference is empty or blank', () => {
  // Primary behavior owned by this requirement: an association shell with no
  // usable web ACL identifier is equivalent to no association at all -> flag.
  it('flags the stage when the association names an empty-string web ACL ARN', () => {
    const result = run(buildTemplate(''));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe(STAGE_LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
  });

  it('flags the stage when the association names a blank (whitespace-only) web ACL ARN', () => {
    const result = run(buildTemplate('   '));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });

  it('flags the stage when the legacy WebACLId property is empty', () => {
    const result = run(buildTemplate('', 'WebACLId'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });

  // Opposite outcome: identical template, only the web ACL identifier is a real
  // value -> the association is usable, so the stage is compliant.
  it('does not flag the stage when the same association names a real web ACL ARN', () => {
    const result = run(
      buildTemplate('arn:aws:wafv2:us-east-1:123456789012:regional/webacl/api-acl/abcd1234'),
    );

    expect(result).toBeNull();
  });
});
