import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.tf.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    rest_api_id: 'aws_api_gateway_rest_api.api',
    stage_name: 'prod',
  },
} as TerraformResource;

const webAcl: TerraformResource = {
  type: 'aws_wafv2_web_acl',
  name: 'acl',
  address: 'aws_wafv2_web_acl.acl',
  values: { name: 'my-acl', scope: 'REGIONAL' },
} as TerraformResource;

function association(resourceArn: string): TerraformResource {
  return {
    type: 'aws_wafv2_web_acl_association',
    name: 'api',
    address: 'aws_wafv2_web_acl_association.api',
    values: {
      resource_arn: resourceArn,
      web_acl_arn: 'aws_wafv2_web_acl.acl',
    },
  } as TerraformResource;
}

function runControl(extraResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: stage,
    allResources: [stage, webAcl, ...extraResources],
  };
  const adapter = new Apigw003TfAdapterFactory().bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 (Terraform) - web ACL association targeting the assessed stage', () => {
  // Primary behavior owned by this requirement: reference form, where HCL wrote
  // `resource_arn = aws_api_gateway_stage.prod.arn` and the plan reader collapsed
  // it to the stage address.
  it('passes when a web ACL association references the assessed stage by address', () => {
    expect(runControl([association('aws_api_gateway_stage.prod')])).toBeNull();
  });

  // Primary behavior, literal form: the protected-resource identifier spells out
  // the API identifier and this stage's name.
  it('passes when a web ACL association names the assessed stage in a literal stage ARN', () => {
    expect(runControl([association('arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod')])).toBeNull();
  });

  // Opposite outcome: same association shape, but it protects a different stage.
  it('flags the stage when the association protects a different stage', () => {
    const result = runControl([association('arn:aws:apigateway:us-east-1::/restapis/abc123/stages/dev')]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });
});
