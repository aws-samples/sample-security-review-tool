import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const API_ADDRESS = 'aws_api_gateway_rest_api.private';
const ENDPOINT_ADDRESS = 'aws_vpc_endpoint.execute_api';

interface EndpointOptions {
  readonly privateDnsEnabled: boolean;
  readonly associated: boolean;
}

function buildResources(options: EndpointOptions): TerraformResource[] {
  const api = {
    type: 'aws_api_gateway_rest_api',
    name: 'private',
    address: API_ADDRESS,
    values: {
      name: 'private-api',
      endpoint_configuration: [
        {
          types: ['PRIVATE'],
          // Reference form: vpc_endpoint_ids = [aws_vpc_endpoint.execute_api.id]
          vpc_endpoint_ids: options.associated ? [ENDPOINT_ADDRESS] : [],
        },
      ],
    },
  } as unknown as TerraformResource;

  const vpcEndpoint = {
    type: 'aws_vpc_endpoint',
    name: 'execute_api',
    address: ENDPOINT_ADDRESS,
    values: {
      service_name: 'com.amazonaws.us-east-1.execute-api',
      vpc_endpoint_type: 'Interface',
      vpc_id: 'vpc-12345678',
      subnet_ids: ['subnet-11111111', 'subnet-22222222'],
      security_group_ids: ['sg-11111111'],
      private_dns_enabled: options.privateDnsEnabled,
    },
  } as unknown as TerraformResource;

  return [api, vpcEndpoint];
}

function runControl(options: EndpointOptions): ScanResult | null {
  const allResources = buildResources(options);
  const context: TfContext = {
    projectName: 'test-project',
    resource: allResources[0]!,
    allResources,
  };
  const adapter = new Apigw005TfAdapterFactory().bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 REQ-07 (Terraform): private API with an execute-api endpoint whose private DNS is disabled and which is not associated', () => {
  it('flags the private REST API when the execute-api VPC endpoint has private DNS disabled and is not associated with the API', () => {
    const result = runControl({ privateDnsEnabled: false, associated: false });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe(API_ADDRESS);
    expect(result?.resourceType).toBe('aws_api_gateway_rest_api');
  });

  it('flags the private REST API when the associated execute-api VPC endpoint still has private DNS explicitly disabled', () => {
    // Isolates the private-DNS-enabled requirement: association alone is not enough.
    const result = runControl({ privateDnsEnabled: false, associated: true });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });

  // Opposite outcome: the nearest compliant input — same private API and same
  // execute-api endpoint (reference form) with subnets and security groups, but
  // private DNS enabled and the endpoint associated with the assessed API.
  it('does not flag the private REST API when the associated execute-api VPC endpoint has private DNS enabled', () => {
    const result = runControl({ privateDnsEnabled: true, associated: true });

    expect(result).toBeNull();
  });
});
