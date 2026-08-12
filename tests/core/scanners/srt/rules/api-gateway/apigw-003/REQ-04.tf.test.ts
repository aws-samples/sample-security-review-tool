import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.tf.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw003TfAdapterFactory();

const prodStage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: { stage_name: 'prod', rest_api_id: 'aws_api_gateway_rest_api.main' },
} as TerraformResource;

const testStage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'test',
  address: 'aws_api_gateway_stage.test',
  values: { stage_name: 'test', rest_api_id: 'aws_api_gateway_rest_api.main' },
} as TerraformResource;

function association(resourceArn: string): TerraformResource {
  return {
    type: 'aws_wafv2_web_acl_association',
    name: 'guard',
    address: 'aws_wafv2_web_acl_association.guard',
    values: { resource_arn: resourceArn, web_acl_arn: 'aws_wafv2_web_acl.edge' },
  } as TerraformResource;
}

function assessProdStage(assoc: TerraformResource): ReturnType<typeof apigw003Control.run> {
  const allResources = [prodStage, testStage, assoc];
  const context: TfContext = {
    projectName: 'api-project',
    resource: prodStage,
    allResources,
  };
  const adapter = factory.bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 REQ-04 (Terraform): association scoped to a different stage of the same API', () => {
  // Primary behavior owned by this requirement (reference form: the HCL wrote
  // resource_arn = aws_api_gateway_stage.test.arn, collapsed to the address).
  it('flags the assessed stage when the association references another stage of the same API', () => {
    const result = assessProdStage(association('aws_api_gateway_stage.test'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });

  // Primary behavior, literal form: a hand-written stage ARN for the test stage
  // of the same REST API still leaves the assessed prod stage unprotected.
  it('flags the assessed stage when a literal ARN targets another stage of the same API', () => {
    const result = assessProdStage(
      association('arn:aws:apigateway:us-east-1::/restapis/aws_api_gateway_rest_api.main/stages/test'),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });

  // Opposite outcome: only the protected stage changes - the association now
  // references the assessed stage, so the stage is covered.
  it('does not flag the assessed stage when the association references that same stage', () => {
    const result = assessProdStage(association('aws_api_gateway_stage.prod'));

    expect(result).toBeNull();
  });
});
