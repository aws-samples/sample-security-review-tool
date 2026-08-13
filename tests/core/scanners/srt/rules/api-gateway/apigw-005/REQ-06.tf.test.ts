import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw005TfAdapterFactory();

/** Reference form: HCL wrote `vpc_endpoint_ids = [aws_vpc_endpoint.only.id]`. */
function restApi(): TerraformResource {
  return {
    type: 'aws_api_gateway_rest_api',
    name: 'private_api',
    address: 'aws_api_gateway_rest_api.private_api',
    values: {
      name: 'private-api',
      endpoint_configuration: [
        {
          types: ['PRIVATE'],
          vpc_endpoint_ids: ['aws_vpc_endpoint.only'],
        },
      ],
    },
  } as unknown as TerraformResource;
}

function vpcEndpoint(serviceName: string): TerraformResource {
  return {
    type: 'aws_vpc_endpoint',
    name: 'only',
    address: 'aws_vpc_endpoint.only',
    values: {
      vpc_id: 'vpc-1234567890abcdef0',
      vpc_endpoint_type: 'Interface',
      service_name: serviceName,
      subnet_ids: ['subnet-aaa111', 'subnet-bbb222'],
      security_group_ids: ['sg-aaa111'],
      private_dns_enabled: true,
    },
  } as unknown as TerraformResource;
}

function run(serviceName: string): ScanResult | null {
  const api = restApi();
  const context: TfContext = {
    projectName: 'test-project',
    resource: api,
    allResources: [api, vpcEndpoint(serviceName)],
  };
  const adapter = factory.bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 REQ-06 (Terraform): private API whose only interface VPC endpoint serves another service', () => {
  // Primary behaviour owned by this requirement: an execute-api endpoint is required.
  it('flags a PRIVATE REST API when the only interface VPC endpoint is for a non-execute-api service', () => {
    const result = run('com.amazonaws.us-east-1.secretsmanager');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceType).toBe('aws_api_gateway_rest_api');
    expect(result?.resourceName).toBe('aws_api_gateway_rest_api.private_api');
  });

  // Nearest input that flips the verdict: same plan, endpoint service is execute-api.
  it('does not flag when that same VPC endpoint serves the API Gateway execute-api service', () => {
    const result = run('com.amazonaws.us-east-1.execute-api');

    expect(result).toBeNull();
  });
});
