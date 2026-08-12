import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.tf.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (APIGW-003): A web ACL association whose protected target is expressed as a broad
 * pattern that necessarily covers every stage of the API owning the assessed stage satisfies
 * the rule — the assessed stage is provably behind a web ACL.
 */

const factory = new Apigw003TfAdapterFactory();

function stage(restApiId: string): TerraformResource {
  return {
    type: 'aws_api_gateway_stage',
    name: 'prod',
    address: 'aws_api_gateway_stage.prod',
    values: { stage_name: 'prod', rest_api_id: restApiId },
  } as unknown as TerraformResource;
}

function association(resourceArn: string): TerraformResource {
  return {
    type: 'aws_wafv2_web_acl_association',
    name: 'stage_protection',
    address: 'aws_wafv2_web_acl_association.stage_protection',
    values: {
      web_acl_arn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/abcd',
      resource_arn: resourceArn,
    },
  } as unknown as TerraformResource;
}

function run(stageResource: TerraformResource, associationResource: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: stageResource,
    allResources: [stageResource, associationResource],
  };
  const adapter = factory.bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 REQ-09 (Terraform): broad association target covering all stages of the API', () => {
  it('passes when the association target wildcards every stage of the API (literal api id)', () => {
    const result = run(
      stage('abc123'),
      association('arn:aws:apigateway:us-east-1::/restapis/abc123/stages/*'),
    );

    expect(result).toBeNull();
  });

  it('passes when the association target wildcards every stage of the API (reference form)', () => {
    const result = run(
      stage('aws_api_gateway_rest_api.main'),
      association('arn:aws:apigateway:us-east-1::/restapis/aws_api_gateway_rest_api.main/stages/*'),
    );

    expect(result).toBeNull();
  });

  // Opposite outcome: same broad wildcard shape, but scoped to a DIFFERENT API, so it cannot
  // cover the assessed stage. (Primary "missing association" behaviour is owned by REQ-01.)
  it('flags when the broad association target covers every stage of a different API', () => {
    const result = run(
      stage('abc123'),
      association('arn:aws:apigateway:us-east-1::/restapis/xyz789/stages/*'),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });
});
