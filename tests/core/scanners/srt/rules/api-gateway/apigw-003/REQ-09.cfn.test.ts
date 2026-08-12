import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (APIGW-003): A web ACL association whose protected target is expressed as a broad
 * pattern that necessarily covers every stage of the API owning the assessed stage satisfies
 * the rule — the assessed stage is provably behind a web ACL.
 */

const factory = new Apigw003CfnAdapterFactory();

function buildTemplate(associationResourceArn: string): Template {
  return {
    Resources: {
      MyApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: { Name: 'my-api' },
      },
      ProdStage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          // !Ref MyApi resolves to the logical id string after preprocessing
          RestApiId: 'MyApi',
          StageName: 'prod',
        },
      },
      StageProtection: {
        Type: 'AWS::WAFv2::WebACLAssociation',
        Properties: {
          WebACLArn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/abcd',
          ResourceArn: associationResourceArn,
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template): ScanResult | null {
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, never>)['ProdStage'],
    logicalId: 'ProdStage',
  };
  const adapter = factory.bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 REQ-09 (CloudFormation): broad association target covering all stages of the API', () => {
  it('passes when the association target wildcards every stage of the assessed stage\'s API', () => {
    const template = buildTemplate('arn:aws:apigateway:us-east-1::/restapis/MyApi/stages/*');

    expect(run(template)).toBeNull();
  });

  // Opposite outcome: same broad wildcard shape, but scoped to a DIFFERENT API, so it cannot
  // cover the assessed stage. (Primary "missing association" behaviour is owned by REQ-01.)
  it('flags when the broad association target covers every stage of a different API', () => {
    const template = buildTemplate('arn:aws:apigateway:us-east-1::/restapis/OtherApi/stages/*');

    const result = run(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });
});
