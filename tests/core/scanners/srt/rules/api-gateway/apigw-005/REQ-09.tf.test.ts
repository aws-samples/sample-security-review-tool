import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const PROJECT_NAME = 'apigw-005-project';
const VPC_ENDPOINT_ADDRESS = 'aws_vpc_endpoint.execute_api';

const factory = new Apigw005TfAdapterFactory();

/**
 * The rest api is PRIVATE and points at an interface VPC endpoint for execute-api
 * with private DNS enabled. `vpc_endpoint_ids` uses the reference form, i.e. the
 * plan reader has collapsed `aws_vpc_endpoint.execute_api.id` to the address.
 */
function buildRestApi(): TerraformResource {
  return {
    type: 'aws_api_gateway_rest_api',
    name: 'private_api',
    address: 'aws_api_gateway_rest_api.private_api',
    values: {
      name: 'private-api',
      endpoint_configuration: [
        {
          types: ['PRIVATE'],
          vpc_endpoint_ids: [VPC_ENDPOINT_ADDRESS],
        },
      ],
    },
  } as unknown as TerraformResource;
}

function buildVpcEndpoint(subnetIds: unknown): TerraformResource {
  const values: Record<string, unknown> = {
    service_name: 'com.amazonaws.us-east-1.execute-api',
    vpc_endpoint_type: 'Interface',
    vpc_id: 'vpc-0123456789abcdef0',
    security_group_ids: ['sg-0123456789abcdef0'],
    private_dns_enabled: true,
  };
  if (subnetIds !== undefined) {
    values['subnet_ids'] = subnetIds;
  }

  return {
    type: 'aws_vpc_endpoint',
    name: 'execute_api',
    address: VPC_ENDPOINT_ADDRESS,
    values,
  } as unknown as TerraformResource;
}

function run(subnetIds: unknown): ScanResult | null {
  const restApi = buildRestApi();
  const allResources = [restApi, buildVpcEndpoint(subnetIds)];
  const context: TfContext = { projectName: PROJECT_NAME, resource: restApi, allResources };
  const adapter = factory.bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 REQ-09 (Terraform): private API whose execute-api VPC endpoint declares no subnets', () => {
  // Primary behavior owned by this requirement.
  it('flags a private API when the referenced VPC endpoint has an empty subnet_ids list', () => {
    const result = run([]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe('aws_api_gateway_rest_api.private_api');
    expect(result?.resourceType).toBe('aws_api_gateway_rest_api');
  });

  it('flags a private API when the referenced VPC endpoint declares no subnet_ids at all', () => {
    const result = run(undefined);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });

  // Opposite outcome: identical configuration except the endpoint declares subnets.
  it('does not flag when the same VPC endpoint declares at least one subnet id', () => {
    const result = run(['subnet-0123456789abcdef0']);

    expect(result).toBeNull();
  });
});
