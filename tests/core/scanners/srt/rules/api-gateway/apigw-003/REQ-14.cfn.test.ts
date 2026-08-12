import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-14 (APIGW-003): A WAFv2 web ACL association targets the assessed stage, and the web ACL it
 * names is declared elsewhere in the same template with an empty rule set.
 * Expected: pass (null) — the ACL's internal rules are a separate concern.
 *
 * Fixtures are written with post-`parseCfnTemplate` values (e.g. `!GetAtt WebAcl.Arn` -> "WebAcl",
 * `!Sub ".../restapis/${RestApi}/stages/prod"` -> ".../restapis/RestApi/stages/prod").
 */

const STAGE_LOGICAL_ID = 'ApiStage';

function buildTemplate(webAclArn: unknown): Template {
  return {
    Resources: {
      RestApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: { Name: 'public-api' },
      },
      [STAGE_LOGICAL_ID]: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'RestApi',
          StageName: 'prod',
          DeploymentId: 'ApiDeployment',
        },
      },
      // Web ACL declared in the same template, with no rules configured.
      WebAcl: {
        Type: 'AWS::WAFv2::WebACL',
        Properties: {
          Name: 'api-acl',
          Scope: 'REGIONAL',
          DefaultAction: { Allow: {} },
          Rules: [],
          VisibilityConfig: {
            CloudWatchMetricsEnabled: true,
            MetricName: 'api-acl',
            SampledRequestsEnabled: true,
          },
        },
      },
      WebAclAssociation: {
        Type: 'AWS::WAFv2::WebACLAssociation',
        Properties: {
          ResourceArn: 'arn:aws:apigateway:us-east-1::/restapis/RestApi/stages/prod',
          WebACLArn: webAclArn,
        },
      },
    },
  } as unknown as Template;
}

function contextFor(template: Template): CfnContext {
  const resources = (template.Resources ?? {}) as Record<string, never>;
  return {
    stackName: 'test-stack',
    template,
    resource: resources[STAGE_LOGICAL_ID],
    logicalId: STAGE_LOGICAL_ID,
  };
}

function assess(template: Template) {
  const context = contextFor(template);
  const adapter = new Apigw003CfnAdapterFactory().bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 CloudFormation - association naming a rule-less web ACL', () => {
  it('passes when the association targets the stage and names a web ACL defined in the template with no rules', () => {
    expect(assess(buildTemplate('WebAcl'))).toBeNull();
  });

  // Opposite outcome: same association targeting the same stage, but it names no web ACL
  // (present-but-empty value). This behaviour belongs to the missing-association requirement.
  it('flags when the same association targets the stage but names an empty web ACL', () => {
    const result = assess(buildTemplate('   '));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });
});
