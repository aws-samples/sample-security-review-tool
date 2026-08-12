import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.tf.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-14 (APIGW-003): A WAFv2 web ACL association targets the assessed stage, and the web ACL it
 * names is declared elsewhere in the same plan with an empty rule set.
 * Expected: pass (null) — the ACL's internal rules are a separate concern.
 */

const restApi: TerraformResource = {
  type: 'aws_api_gateway_rest_api',
  name: 'api',
  address: 'aws_api_gateway_rest_api.api',
  values: { name: 'public-api' },
} as unknown as TerraformResource;

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: { rest_api_id: 'aws_api_gateway_rest_api.api', stage_name: 'prod' },
} as unknown as TerraformResource;

// Web ACL declared in the same plan, with no rules configured.
const webAcl: TerraformResource = {
  type: 'aws_wafv2_web_acl',
  name: 'acl',
  address: 'aws_wafv2_web_acl.acl',
  values: {
    name: 'api-acl',
    scope: 'REGIONAL',
    default_action: [{ allow: [{}] }],
    rule: [],
  },
} as unknown as TerraformResource;

function association(webAclArn: unknown): TerraformResource {
  return {
    type: 'aws_wafv2_web_acl_association',
    name: 'assoc',
    address: 'aws_wafv2_web_acl_association.assoc',
    // Reference form: HCL wrote aws_api_gateway_stage.prod.arn / aws_wafv2_web_acl.acl.arn
    values: { resource_arn: 'aws_api_gateway_stage.prod', web_acl_arn: webAclArn },
  } as unknown as TerraformResource;
}

function assess(assoc: TerraformResource) {
  const allResources = [restApi, stage, webAcl, assoc];
  const context: TfContext = { projectName: 'test-project', resource: stage, allResources };
  const adapter = new Apigw003TfAdapterFactory().bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 Terraform - association naming a rule-less web ACL', () => {
  it('passes when the reference-form association targets the stage and names a web ACL with no rules', () => {
    expect(assess(association('aws_wafv2_web_acl.acl'))).toBeNull();
  });

  it('passes when the association names the web ACL by literal ARN and that ACL has no rules', () => {
    expect(
      assess(association('arn:aws:wafv2:us-east-1:123456789012:regional/webacl/api-acl/abcd1234')),
    ).toBeNull();
  });

  // Opposite outcome: same association targeting the same stage, but it names no web ACL
  // (present-but-empty value). This behaviour belongs to the missing-association requirement.
  it('flags when the same association targets the stage but names an empty web ACL', () => {
    const result = assess(association('   '));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });
});
