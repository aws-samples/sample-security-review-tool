import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STAGE_LOGICAL_ID = 'PrivateApiStage';
const factory = new Apigw003CfnAdapterFactory();

/**
 * Builds a template whose REST API is reachable only from inside a VPC
 * (EndpointConfiguration Types: PRIVATE). `!Ref PrivateRestApi` has already been
 * resolved by preprocessing to the logical id string "PrivateRestApi".
 */
function buildTemplate(extraResources: Record<string, unknown> = {}): Template {
  return {
    Resources: {
      PrivateRestApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'internal-only-api',
          EndpointConfiguration: { Types: ['PRIVATE'] },
        },
      },
      [STAGE_LOGICAL_ID]: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'PrivateRestApi',
          StageName: 'prod',
          DeploymentId: 'ApiDeployment',
        },
      },
      ...extraResources,
    },
  } as unknown as Template;
}

function bind(template: Template): { adapter: Apigw003Adapter; context: CfnContext } {
  const resource = (template.Resources as Record<string, Resource>)[STAGE_LOGICAL_ID];
  const context: CfnContext = {
    stackName: 'private-api-stack',
    template,
    resource,
    logicalId: STAGE_LOGICAL_ID,
  };
  return { adapter: factory.bind(context), context };
}

function run(template: Template): ScanResult | null {
  const { adapter, context } = bind(template);
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 (CloudFormation): private-endpoint REST API stages are not exempt from the WAF requirement', () => {
  // Primary behavior owned by APIGW-003: every REST API stage without a web ACL is flagged,
  // with no exemption based on endpoint type.
  it('flags a stage of a PRIVATE-endpoint REST API that has no web ACL association', () => {
    const result = run(buildTemplate());

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
    expect(result?.resourceName).toBe(STAGE_LOGICAL_ID);
  });

  // Opposite outcome: identical private-endpoint stage, but a web ACL is associated with it.
  it('does not flag the same PRIVATE-endpoint stage when a web ACL is associated with it', () => {
    const result = run(
      buildTemplate({
        StageWebAclAssociation: {
          Type: 'AWS::WAFv2::WebACLAssociation',
          Properties: {
            ResourceArn:
              'arn:aws:apigateway:us-east-1::/restapis/PrivateRestApi/stages/prod',
            WebACLArn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/api-acl/abc',
          },
        },
      }),
    );

    expect(result).toBeNull();
  });
});
