import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw003CfnAdapterFactory();

/**
 * Builds a template with two stages of the same REST API and a single web ACL
 * association whose protected target is decided by the caller.
 * Values are written already resolved, as parseCfnTemplate would leave them
 * (!Ref RestApi -> "RestApi").
 */
function buildTemplate(associationResourceArn: string): Template {
  return {
    Resources: {
      RestApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: { Name: 'orders-api' },
      },
      ProdStage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: { RestApiId: 'RestApi', StageName: 'prod', DeploymentId: 'Deployment' },
      },
      TestStage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: { RestApiId: 'RestApi', StageName: 'test', DeploymentId: 'Deployment' },
      },
      WebAcl: {
        Type: 'AWS::WAFv2::WebACL',
        Properties: { Name: 'edge-acl', Scope: 'REGIONAL' },
      },
      StageAssociation: {
        Type: 'AWS::WAFv2::WebACLAssociation',
        Properties: {
          WebACLArn: 'WebAcl',
          ResourceArn: associationResourceArn,
        },
      },
    },
  } as unknown as Template;
}

function assessProdStage(template: Template): ReturnType<typeof apigw003Control.run> {
  const resource = (template.Resources as Record<string, any>)['ProdStage'];
  const context: CfnContext = {
    stackName: 'api-stack',
    template,
    resource,
    logicalId: 'ProdStage',
  };
  const adapter = factory.bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 REQ-04 (CloudFormation): association scoped to a different stage of the same API', () => {
  // Primary behavior owned by this requirement: the association protects the
  // test stage of the same REST API, so the assessed prod stage is unfiltered.
  it('flags the assessed stage when the association targets another stage of the same API', () => {
    const template = buildTemplate('arn:aws:apigateway:us-east-1::/restapis/RestApi/stages/test');

    const result = assessProdStage(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe('ProdStage');
  });

  // Opposite outcome: only the protected stage changes - the association now
  // targets the assessed stage itself, so the stage is covered.
  it('does not flag the assessed stage when the association targets that same stage', () => {
    const template = buildTemplate('arn:aws:apigateway:us-east-1::/restapis/RestApi/stages/prod');

    const result = assessProdStage(template);

    expect(result).toBeNull();
  });
});
