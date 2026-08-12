import { describe, it, expect } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.tf.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw003TfAdapterFactory();

const stage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    stage_name: 'prod',
    rest_api_id: 'aws_api_gateway_rest_api.api',
    deployment_id: 'aws_api_gateway_deployment.dep',
  },
} as unknown as TerraformResource;

const restApi: TerraformResource = {
  type: 'aws_api_gateway_rest_api',
  name: 'api',
  address: 'aws_api_gateway_rest_api.api',
  values: { name: 'public-api' },
} as unknown as TerraformResource;

// Reference form — user wrote `resource_arn = aws_api_gateway_stage.prod.arn` in HCL,
// which the plan reader collapses to the stage address.
const wafAssociation: TerraformResource = {
  type: 'aws_wafv2_web_acl_association',
  name: 'api',
  address: 'aws_wafv2_web_acl_association.api',
  values: {
    resource_arn: 'aws_api_gateway_stage.prod',
    web_acl_arn: 'aws_wafv2_web_acl.acl',
  },
} as unknown as TerraformResource;

const webAcl: TerraformResource = {
  type: 'aws_wafv2_web_acl',
  name: 'acl',
  address: 'aws_wafv2_web_acl.acl',
  values: { name: 'api-acl', scope: 'REGIONAL' },
} as unknown as TerraformResource;

function run(allResources: TerraformResource[]) {
  const context: TfContext = { projectName: 'test-project', resource: stage, allResources };
  const adapter = factory.bind(context) as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 REQ-01 (Terraform): stage with no web ACL association anywhere in the plan', () => {
  it('flags an API Gateway stage when the plan contains no web application firewall association of any kind', () => {
    const result = run([restApi, stage]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
  });

  // Opposite outcome: nearest input that flips the verdict — same stage, but a
  // web ACL association referencing it exists. Primary behavior for the
  // "association present" case is owned by the associated-stage requirement.
  it('does not flag the same stage when a wafv2 web acl association referencing it is present', () => {
    const result = run([restApi, stage, webAcl, wafAssociation]);

    expect(result).toBeNull();
  });
});
