import { describe, it, expect } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.tf.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    stage_name: 'prod',
    rest_api_id: 'aws_api_gateway_rest_api.api',
  },
} as unknown as TerraformResource;

function runControl(association: TerraformResource) {
  const allResources = [stage, association];
  const context: TfContext = {
    projectName: 'test-project',
    resource: stage,
    allResources,
  };
  const adapter = new Apigw003TfAdapterFactory().bind(context) as Apigw003Adapter;
  return { result: apigw003Control.run(adapter, context), adapter };
}

describe('APIGW-003 (Terraform) — legacy WAF Classic association only', () => {
  // Primary behavior owned by this requirement: WAF Classic (wafregional) is
  // end-of-life, so a stage covered only by a Classic association is unprotected.
  it('flags a stage associated only with a WAF Classic (wafregional) web ACL — reference form', () => {
    const classicAssociation = {
      type: 'aws_wafregional_web_acl_association',
      name: 'legacy',
      address: 'aws_wafregional_web_acl_association.legacy',
      values: {
        resource_arn: 'aws_api_gateway_stage.prod',
        web_acl_id: 'aws_wafregional_web_acl.legacy',
      },
    } as unknown as TerraformResource;

    const { result, adapter } = runControl(classicAssociation);

    expect(adapter.hasWebAclAssociation()).toBe(false);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
  });

  // Opposite outcome: identical wiring, only the WAF generation changes.
  it('does not flag the same stage when the association is current-generation wafv2 — reference form', () => {
    const v2Association = {
      type: 'aws_wafv2_web_acl_association',
      name: 'current',
      address: 'aws_wafv2_web_acl_association.current',
      values: {
        resource_arn: 'aws_api_gateway_stage.prod',
        web_acl_arn: 'aws_wafv2_web_acl.current',
      },
    } as unknown as TerraformResource;

    const { result, adapter } = runControl(v2Association);

    expect(adapter.hasWebAclAssociation()).toBe(true);
    expect(result).toBeNull();
  });
});
