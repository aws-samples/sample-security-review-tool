import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import { Apigw003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    stage_name: 'prod',
    // reference form: rest_api_id = aws_api_gateway_rest_api.api.id
    rest_api_id: 'aws_api_gateway_rest_api.api',
  },
} as unknown as TerraformResource;

/** Association wired by reference (resource_arn = aws_api_gateway_stage.prod.arn). */
function association(webAcl: unknown, key: 'web_acl_arn' | 'web_acl_id' = 'web_acl_arn'): TerraformResource {
  return {
    type: 'aws_wafv2_web_acl_association',
    name: 'stage',
    address: 'aws_wafv2_web_acl_association.stage',
    values: {
      resource_arn: stage.address,
      [key]: webAcl,
    },
  } as unknown as TerraformResource;
}

function run(assoc: TerraformResource) {
  const allResources = [stage, assoc];
  const context: TfContext = { projectName: 'test-project', resource: stage, allResources };
  const adapter = new Apigw003TfAdapterFactory().bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 Terraform - association present but web ACL reference is empty or blank', () => {
  // Primary behavior owned by this requirement: an association with no usable
  // web ACL identifier provides no protection -> flag.
  it('flags the stage when the association has an empty web_acl_arn', () => {
    const result = run(association(''));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
  });

  it('flags the stage when the association has a blank (whitespace-only) web_acl_arn', () => {
    const result = run(association('   '));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });

  it('flags the stage when the legacy web_acl_id is empty', () => {
    const result = run(association('', 'web_acl_id'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });

  // Opposite outcome: identical association, only the web ACL identifier is a
  // real reference -> compliant.
  it('does not flag the stage when the same association references a real web ACL', () => {
    const result = run(association('aws_wafv2_web_acl.api'));

    expect(result).toBeNull();
  });
});
