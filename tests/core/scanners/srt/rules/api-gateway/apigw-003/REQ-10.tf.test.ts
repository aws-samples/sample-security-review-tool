import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.tf.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STAGE_ADDRESS = 'aws_api_gateway_stage.prod';

function stage(restApiId: string): TerraformResource {
  return {
    type: 'aws_api_gateway_stage',
    name: 'prod',
    address: STAGE_ADDRESS,
    values: { stage_name: 'prod', rest_api_id: restApiId },
  } as TerraformResource;
}

function association(protectedApiId: string): TerraformResource {
  return {
    type: 'aws_wafv2_web_acl_association',
    name: 'edge',
    address: 'aws_wafv2_web_acl_association.edge',
    values: {
      web_acl_arn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/edge-acl/abc123',
      resource_arn: `arn:aws:apigateway:us-east-1::/restapis/${protectedApiId}/stages/*`,
    },
  } as TerraformResource;
}

function runControl(stageResource: TerraformResource, associationResource: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: stageResource,
    allResources: [stageResource, associationResource],
  };
  const adapter = new Apigw003TfAdapterFactory().bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 (Terraform): wildcard web ACL association scoped to a different API', () => {
  // Primary behaviour owned by this requirement. Reference form: the stage's
  // rest_api_id was written as aws_api_gateway_rest_api.main.id in HCL and has
  // been collapsed to the resource address by the plan reader.
  it('flags the stage when the wildcard association targets another API (reference form)', () => {
    const result = runControl(stage('aws_api_gateway_rest_api.main'), association('other-api-id'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe(STAGE_ADDRESS);
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
  });

  // Same scenario with a literal rest_api_id written directly in HCL.
  it('flags the stage when the wildcard association targets another API (literal form)', () => {
    const result = runControl(stage('main-api-id'), association('other-api-id'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });

  // Opposite outcome: only the API the wildcard is scoped to changes. Scoped to
  // the assessed stage's own API, the wildcard provably covers this stage.
  it('does not flag the stage when the same wildcard is scoped to the stage owning API', () => {
    const result = runControl(stage('main-api-id'), association('main-api-id'));

    expect(result).toBeNull();
  });
});
