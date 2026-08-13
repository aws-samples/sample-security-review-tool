import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const PROJECT = 'test-project';
const VPC_ENDPOINT_ADDRESS = 'aws_vpc_endpoint.execute_api';

function restApi(): TerraformResource {
  return {
    type: 'aws_api_gateway_rest_api',
    name: 'private_api',
    address: 'aws_api_gateway_rest_api.private_api',
    values: {
      name: 'private-api',
      endpoint_configuration: [{
        types: ['PRIVATE'],
        // reference form: vpc_endpoint_ids = [aws_vpc_endpoint.execute_api.id]
        vpc_endpoint_ids: [VPC_ENDPOINT_ADDRESS],
      }],
    },
  } as unknown as TerraformResource;
}

function vpcEndpoint(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_vpc_endpoint',
    name: 'execute_api',
    address: VPC_ENDPOINT_ADDRESS,
    values,
  } as unknown as TerraformResource;
}

function run(endpoint: TerraformResource): ScanResult | null {
  const api = restApi();
  const context: TfContext = {
    projectName: PROJECT,
    resource: api,
    allResources: [api, endpoint],
  };
  const adapter = new Apigw005TfAdapterFactory().bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 (Terraform) - private API with a VPC endpoint that declares no security groups', () => {
  // Primary behaviour owned by this requirement: security_group_ids are mandatory on the execute-api VPC endpoint.
  it('flags a private REST API whose execute-api VPC endpoint omits security_group_ids', () => {
    const result = run(vpcEndpoint({
      service_name: 'com.amazonaws.us-east-1.execute-api',
      vpc_endpoint_type: 'Interface',
      vpc_id: 'vpc-123',
      subnet_ids: ['subnet-aaa', 'subnet-bbb'],
      private_dns_enabled: true,
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe('aws_api_gateway_rest_api.private_api');
  });

  it('flags a private REST API whose execute-api VPC endpoint declares an empty security_group_ids list', () => {
    const result = run(vpcEndpoint({
      service_name: 'com.amazonaws.us-east-1.execute-api',
      vpc_endpoint_type: 'Interface',
      vpc_id: 'vpc-123',
      subnet_ids: ['subnet-aaa'],
      security_group_ids: [],
      private_dns_enabled: true,
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });

  // Opposite outcome: identical fixture except the endpoint declares security group ids.
  it('does not flag when the same execute-api VPC endpoint declares security_group_ids', () => {
    const result = run(vpcEndpoint({
      service_name: 'com.amazonaws.us-east-1.execute-api',
      vpc_endpoint_type: 'Interface',
      vpc_id: 'vpc-123',
      subnet_ids: ['subnet-aaa', 'subnet-bbb'],
      security_group_ids: ['sg-123'],
      private_dns_enabled: true,
    }));

    expect(result).toBeNull();
  });
});
