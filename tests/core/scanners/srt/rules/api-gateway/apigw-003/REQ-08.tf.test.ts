import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import { Apigw003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-08 (APIGW-003): Several web ACL associations exist targeting different stages,
 * and one of them targets the assessed stage -> PASS (the stage is protected).
 */

const WEB_ACL = 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/app-acl/1111';

const assessedStage = (restApiId: string): TerraformResource =>
  ({
    type: 'aws_api_gateway_stage',
    name: 'prod',
    address: 'aws_api_gateway_stage.prod',
    values: { stage_name: 'prod', rest_api_id: restApiId },
  }) as unknown as TerraformResource;

const otherStages: TerraformResource[] = [
  {
    type: 'aws_api_gateway_stage',
    name: 'dev',
    address: 'aws_api_gateway_stage.dev',
    values: { stage_name: 'dev', rest_api_id: 'aws_api_gateway_rest_api.main' },
  },
  {
    type: 'aws_api_gateway_stage',
    name: 'staging',
    address: 'aws_api_gateway_stage.staging',
    values: { stage_name: 'staging', rest_api_id: 'aws_api_gateway_rest_api.main' },
  },
] as unknown as TerraformResource[];

// Associations aimed at other stages (reference form).
const unrelatedAssociations: TerraformResource[] = [
  {
    type: 'aws_wafv2_web_acl_association',
    name: 'dev',
    address: 'aws_wafv2_web_acl_association.dev',
    values: { web_acl_arn: WEB_ACL, resource_arn: 'aws_api_gateway_stage.dev' },
  },
  {
    type: 'aws_wafv2_web_acl_association',
    name: 'staging',
    address: 'aws_wafv2_web_acl_association.staging',
    values: { web_acl_arn: WEB_ACL, resource_arn: 'aws_api_gateway_stage.staging' },
  },
] as unknown as TerraformResource[];

const association = (name: string, resourceArn: string): TerraformResource =>
  ({
    type: 'aws_wafv2_web_acl_association',
    name,
    address: `aws_wafv2_web_acl_association.${name}`,
    values: { web_acl_arn: WEB_ACL, resource_arn: resourceArn },
  }) as unknown as TerraformResource;

function bind(stage: TerraformResource, associations: TerraformResource[]): { adapter: Apigw003Adapter; context: TfContext } {
  const context: TfContext = {
    projectName: 'test-project',
    resource: stage,
    allResources: [stage, ...otherStages, ...associations],
  };
  return { adapter: new Apigw003TfAdapterFactory().bind(context), context };
}

describe('APIGW-003 REQ-08 (Terraform)', () => {
  it('passes when one of several associations references the assessed stage', () => {
    const stage = assessedStage('aws_api_gateway_rest_api.main');
    const { adapter, context } = bind(stage, [
      ...unrelatedAssociations,
      association('prod', 'aws_api_gateway_stage.prod'),
    ]);

    expect(adapter.hasWebAclAssociation()).toBe(true);
    expect(apigw003Control.run(adapter, context)).toBeNull();
  });

  it('passes when the covering association uses a literal stage ARN', () => {
    const stage = assessedStage('abc123');
    const { adapter, context } = bind(stage, [
      ...unrelatedAssociations,
      association('prod', 'arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod'),
    ]);

    expect(adapter.hasWebAclAssociation()).toBe(true);
    expect(apigw003Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: the same several associations all target other stages, so the
  // missing-association behavior (owned by APIGW-003) must produce a finding.
  it('flags the stage when none of the several associations targets the assessed stage', () => {
    const stage = assessedStage('aws_api_gateway_rest_api.main');
    const { adapter, context } = bind(stage, unrelatedAssociations);

    expect(adapter.hasWebAclAssociation()).toBe(false);
    const result = apigw003Control.run(adapter, context);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });
});
