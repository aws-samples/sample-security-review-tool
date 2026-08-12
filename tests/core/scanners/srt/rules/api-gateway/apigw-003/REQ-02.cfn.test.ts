import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STAGE_LOGICAL_ID = 'ProdStage';

/**
 * Builds a template containing a REST API, the assessed stage, and (optionally)
 * a WAF web ACL association whose protected-resource ARN is `associationArn`.
 *
 * Values below are written as they appear AFTER parseCfnTemplate preprocessing:
 * `!Ref MyApi` collapses to the logical id string "MyApi", and a `!Sub`
 * building the stage ARN collapses to the concatenated literal.
 */
function buildTemplate(associationArn?: string): Template {
  const template: Record<string, unknown> = {
    Resources: {
      MyApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: { Name: 'my-api' },
      },
      [STAGE_LOGICAL_ID]: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'MyApi',
          StageName: 'prod',
          DeploymentId: 'MyDeployment',
        },
      },
      MyWebAcl: {
        Type: 'AWS::WAFv2::WebACL',
        Properties: { Name: 'my-acl', Scope: 'REGIONAL' },
      },
    },
  };

  if (associationArn !== undefined) {
    (template.Resources as Record<string, unknown>)['ApiWafAssociation'] = {
      Type: 'AWS::WAFv2::WebACLAssociation',
      Properties: {
        ResourceArn: associationArn,
        WebACLArn: 'MyWebAcl',
      },
    };
  }

  return template as unknown as Template;
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

describe('APIGW-003 (CloudFormation) - web ACL association targeting the assessed stage', () => {
  // Primary behavior owned by this requirement: an association whose protected
  // resource is this stage (API id + stage name) and which names a web ACL passes.
  it('passes when a web ACL association references the assessed stage as its protected resource', () => {
    const template = buildTemplate('arn:aws:apigateway:us-east-1::/restapis/MyApi/stages/prod');

    expect(runControl(template)).toBeNull();
  });

  // Opposite outcome: identical association, but the protected resource is a
  // different stage of the same API, so the assessed stage is unprotected.
  it('flags the stage when the association protects a different stage of the same API', () => {
    const template = buildTemplate('arn:aws:apigateway:us-east-1::/restapis/MyApi/stages/dev');

    const result = runControl(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe(STAGE_LOGICAL_ID);
  });

  it('passes when the ARN references the stage resource, since Ref on a stage returns its name', () => {
    const template = buildTemplate(`arn:aws:apigateway:us-east-1::/restapis/MyApi/stages/${STAGE_LOGICAL_ID}`);

    expect(runControl(template)).toBeNull();
  });

  it('flags the stage when the ARN references a different stage resource', () => {
    const template = buildTemplate('arn:aws:apigateway:us-east-1::/restapis/MyApi/stages/OtherStage');

    const result = runControl(template);

    expect(result).not.toBeNull();
    expect(result?.resourceName).toBe(STAGE_LOGICAL_ID);
  });
});
