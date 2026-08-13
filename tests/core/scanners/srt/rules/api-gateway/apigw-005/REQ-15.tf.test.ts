import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const publicRestApi: TerraformResource = {
  type: 'aws_api_gateway_rest_api',
  name: 'public',
  address: 'aws_api_gateway_rest_api.public',
  values: {
    name: 'public-api',
    endpoint_configuration: [{ types: ['REGIONAL'] }],
  },
} as unknown as TerraformResource;

/** EC2 instance wired into a subnet by reference — a VPC-attached caller of the API. */
const vpcAttachedInstance: TerraformResource = {
  type: 'aws_instance',
  name: 'app',
  address: 'aws_instance.app',
  values: {
    ami: 'ami-12345678',
    instance_type: 't3.micro',
    subnet_id: 'aws_subnet.private',
  },
} as unknown as TerraformResource;

const privateSubnet: TerraformResource = {
  type: 'aws_subnet',
  name: 'private',
  address: 'aws_subnet.private',
  values: { cidr_block: '10.0.1.0/24', vpc_id: 'aws_vpc.main' },
} as unknown as TerraformResource;

function runControl(allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: publicRestApi,
    allResources,
  };
  const adapter = new Apigw005TfAdapterFactory().bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 (Terraform) - public REST API with no VPC-attached callers', () => {
  // Primary behavior owned by this requirement: the rule only governs APIs whose
  // callers live inside a VPC, so a public endpoint with no VPC-attached compute passes.
  it('passes a REGIONAL (public) REST API when the plan has no VPC-attached compute resources', () => {
    const result = runControl([publicRestApi]);

    expect(result).toBeNull();
  });

  // Opposite outcome: identical public REST API, but now a VPC-attached caller exists.
  it('flags the same public REST API when the plan contains a VPC-attached EC2 instance', () => {
    const result = runControl([publicRestApi, vpcAttachedInstance, privateSubnet]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe('aws_api_gateway_rest_api.public');
  });
});
