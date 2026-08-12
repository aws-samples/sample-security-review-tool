import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * APIGW-003 — Public-facing API Gateway stages must have an AWS WAF web ACL associated.
 *
 * REQ-03: A web ACL association whose protected target is a stage of a DIFFERENT API
 * confers no protection on the assessed stage, so the assessed stage must be flagged.
 */

const factory = new Apigw003TfAdapterFactory();

// Assessed stage: stage "prod" of aws_api_gateway_rest_api.assessed
const assessedStage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'assessed',
  address: 'aws_api_gateway_stage.assessed',
  values: {
    stage_name: 'prod',
    rest_api_id: 'aws_api_gateway_rest_api.assessed',
  },
} as unknown as TerraformResource;

// A stage named "prod" belonging to a completely different REST API.
const otherStage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'other',
  address: 'aws_api_gateway_stage.other',
  values: {
    stage_name: 'prod',
    rest_api_id: 'aws_api_gateway_rest_api.other',
  },
} as unknown as TerraformResource;

function run(association: TerraformResource) {
  const allResources = [assessedStage, otherStage, association];
  const context: TfContext = {
    projectName: 'test-project',
    resource: assessedStage,
    allResources,
  };
  return apigw003Control.run(factory.bind(context), context);
}

describe('APIGW-003 REQ-03 (Terraform): association protecting a stage of another API', () => {
  it('flags the assessed stage when the association ARN names the same stage name under a different API', () => {
    const association: TerraformResource = {
      type: 'aws_wafv2_web_acl_association',
      name: 'other',
      address: 'aws_wafv2_web_acl_association.other',
      values: {
        web_acl_arn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/shared-acl/abcd',
        // Protects stage "prod" of a DIFFERENT rest api id.
        resource_arn: 'arn:aws:apigateway:us-east-1::/restapis/otherapi999/stages/prod',
      },
    } as unknown as TerraformResource;

    const result = run(association);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.assessed');
  });

  // Reference form — resource_arn = aws_api_gateway_stage.other.arn collapses to the address.
  it('flags the assessed stage when the association references the other API stage resource', () => {
    const association: TerraformResource = {
      type: 'aws_wafv2_web_acl_association',
      name: 'other',
      address: 'aws_wafv2_web_acl_association.other',
      values: {
        web_acl_arn: 'aws_wafv2_web_acl.shared',
        resource_arn: 'aws_api_gateway_stage.other',
      },
    } as unknown as TerraformResource;

    const result = run(association);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });

  // Opposite outcome — the association names the ASSESSED stage, so it is protected.
  // Owned by the passing-case requirement; included so this file cannot be satisfied
  // by a control that flags everything.
  it('does not flag when the association references the assessed stage', () => {
    const association: TerraformResource = {
      type: 'aws_wafv2_web_acl_association',
      name: 'assessed',
      address: 'aws_wafv2_web_acl_association.assessed',
      values: {
        web_acl_arn: 'aws_wafv2_web_acl.shared',
        resource_arn: 'aws_api_gateway_stage.assessed',
      },
    } as unknown as TerraformResource;

    const result = run(association);

    expect(result).toBeNull();
  });
});
