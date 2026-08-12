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
    rest_api_id: 'aws_api_gateway_rest_api.api',
  },
} as TerraformResource;

function association(resourceArn: unknown): TerraformResource {
  return {
    type: 'aws_wafv2_web_acl_association',
    name: 'stage',
    address: 'aws_wafv2_web_acl_association.stage',
    values: {
      web_acl_arn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/api-acl/abc123',
      resource_arn: resourceArn,
    },
  } as TerraformResource;
}

function runControl(assoc: TerraformResource) {
  const allResources = [stage, assoc];
  const context: TfContext = {
    projectName: 'test-project',
    resource: stage,
    allResources,
  };
  const adapter = new Apigw003TfAdapterFactory().bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 [Terraform] REQ-06: web ACL association with an empty protected-target value', () => {
  // Primary behavior owned by this requirement: resource_arn present but empty means the
  // association cannot be matched to this stage -> flag the stage as unprotected.
  it('flags the stage when the association resource_arn is an empty string', () => {
    const result = runControl(association(''));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
  });

  it('flags the stage when the association resource_arn is whitespace only', () => {
    const result = runControl(association('   '));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });

  // Opposite outcome (nearest input that flips the verdict): reference form, where
  // resource_arn = aws_api_gateway_stage.prod.arn collapses to the stage address.
  it('does not flag the stage when the same association references this stage', () => {
    const result = runControl(association('aws_api_gateway_stage.prod'));

    expect(result).toBeNull();
  });
});
