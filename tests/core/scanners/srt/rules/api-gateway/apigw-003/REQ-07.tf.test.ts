import { describe, expect, it } from 'vitest';
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
    // reference form: rest_api_id = aws_api_gateway_rest_api.api.id
    rest_api_id: 'aws_api_gateway_rest_api.api',
  },
} as TerraformResource;

function association(resourceArn: unknown): TerraformResource {
  return {
    type: 'aws_wafv2_web_acl_association',
    name: 'stage',
    address: 'aws_wafv2_web_acl_association.stage',
    values: {
      web_acl_arn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/abcd1234',
      resource_arn: resourceArn,
    },
  } as TerraformResource;
}

function bindStage(assoc: TerraformResource): { adapter: Apigw003Adapter; context: TfContext } {
  const context: TfContext = {
    projectName: 'test-project',
    resource: stage,
    allResources: [stage, assoc],
  };
  const adapter = new Apigw003TfAdapterFactory().bind(context);
  return { adapter, context };
}

describe('APIGW-003 (Terraform) - unresolvable web ACL association target', () => {
  // Primary behaviour owned by this requirement: unresolvable coverage evidence passes.
  it('passes when resource_arn is null because it is unknown at plan time', () => {
    const { adapter, context } = bindStage(association(null));

    expect(adapter.hasWebAclAssociation()).toBe(true);
    expect(apigw003Control.run(adapter, context)).toBeNull();
  });

  it('passes when resource_arn is absent from planned values', () => {
    const assoc = {
      type: 'aws_wafv2_web_acl_association',
      name: 'stage',
      address: 'aws_wafv2_web_acl_association.stage',
      values: { web_acl_arn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/abcd1234' },
    } as TerraformResource;
    const { adapter, context } = bindStage(assoc);

    expect(adapter.hasWebAclAssociation()).toBe(true);
    expect(apigw003Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: same association, but with a resolved reference-form target
  // that designates a different stage, must be flagged.
  it('flags the stage when resource_arn resolves to a different stage resource', () => {
    const { adapter, context } = bindStage(association('aws_api_gateway_stage.other'));

    expect(adapter.hasWebAclAssociation()).toBe(false);
    const result = apigw003Control.run(adapter, context);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });
});
