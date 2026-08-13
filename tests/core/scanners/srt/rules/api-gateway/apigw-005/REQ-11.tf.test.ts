import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const REST_API_ADDRESS = 'aws_api_gateway_rest_api.private';

/**
 * A PRIVATE REST API referencing several interface VPC endpoints (reference form,
 * i.e. the addresses the plan reader produces for `aws_vpc_endpoint.x.id`):
 * - a fully configured execute-api endpoint,
 * - an execute-api endpoint missing subnets/security groups,
 * - a fully configured endpoint for another service (S3).
 */
function buildResources(options: { privateDnsOnApiGatewayEndpoint: boolean }): {
  restApi: TerraformResource;
  allResources: TerraformResource[];
} {
  const restApi: TerraformResource = {
    type: 'aws_api_gateway_rest_api',
    name: 'private',
    address: REST_API_ADDRESS,
    values: {
      name: 'private-api',
      endpoint_configuration: [
        {
          types: ['PRIVATE'],
          vpc_endpoint_ids: [
            'aws_vpc_endpoint.incomplete_api',
            'aws_vpc_endpoint.s3',
            'aws_vpc_endpoint.api',
          ],
        },
      ],
    },
  } as unknown as TerraformResource;

  const apiEndpoint: TerraformResource = {
    type: 'aws_vpc_endpoint',
    name: 'api',
    address: 'aws_vpc_endpoint.api',
    values: {
      vpc_endpoint_type: 'Interface',
      service_name: 'com.amazonaws.us-east-1.execute-api',
      subnet_ids: ['subnet-a', 'subnet-b'],
      security_group_ids: ['sg-api'],
      private_dns_enabled: options.privateDnsOnApiGatewayEndpoint,
    },
  } as unknown as TerraformResource;

  const incompleteApiEndpoint: TerraformResource = {
    type: 'aws_vpc_endpoint',
    name: 'incomplete_api',
    address: 'aws_vpc_endpoint.incomplete_api',
    values: {
      vpc_endpoint_type: 'Interface',
      service_name: 'com.amazonaws.us-east-1.execute-api',
      subnet_ids: [],
      security_group_ids: [],
      private_dns_enabled: false,
    },
  } as unknown as TerraformResource;

  const s3Endpoint: TerraformResource = {
    type: 'aws_vpc_endpoint',
    name: 's3',
    address: 'aws_vpc_endpoint.s3',
    values: {
      vpc_endpoint_type: 'Interface',
      service_name: 'com.amazonaws.us-east-1.s3',
      subnet_ids: ['subnet-a'],
      security_group_ids: ['sg-s3'],
      private_dns_enabled: true,
    },
  } as unknown as TerraformResource;

  return {
    restApi,
    allResources: [restApi, incompleteApiEndpoint, s3Endpoint, apiEndpoint],
  };
}

function run(options: { privateDnsOnApiGatewayEndpoint: boolean }): ScanResult | null {
  const { restApi, allResources } = buildResources(options);
  const context: TfContext = {
    projectName: 'test-project',
    resource: restApi,
    allResources,
  };
  const adapter = new Apigw005TfAdapterFactory().bind(context);
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 (Terraform) - private API with a mix of VPC endpoints', () => {
  // Primary behavior owned by this requirement: one fully configured execute-api
  // interface endpoint is enough, even alongside incomplete or unrelated endpoints.
  it('does not report a finding when at least one execute-api endpoint is fully configured', () => {
    expect(run({ privateDnsOnApiGatewayEndpoint: true })).toBeNull();
  });

  // Opposite outcome: identical plan except the only complete execute-api endpoint
  // has private DNS disabled, so no endpoint provides private access.
  it('reports a finding when no execute-api endpoint is fully configured', () => {
    const result = run({ privateDnsOnApiGatewayEndpoint: false });
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe(REST_API_ADDRESS);
  });
});
