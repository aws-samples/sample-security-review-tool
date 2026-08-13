import { describe, expect, it } from 'vitest';

import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw005TfAdapterFactory();

function scan(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  const adapter: Apigw005Adapter = factory.bind(context);
  return apigw005Control.run(adapter, context);
}

const vpcEndpoint: TerraformResource = {
  type: 'aws_vpc_endpoint',
  name: 'api',
  address: 'aws_vpc_endpoint.api',
  values: {
    service_name: 'com.amazonaws.us-east-1.execute-api',
    vpc_endpoint_type: 'Interface',
    vpc_id: 'vpc-0123456789abcdef0',
    subnet_ids: ['subnet-aaa111', 'subnet-bbb222'],
    security_group_ids: ['sg-0123456789abcdef0'],
    private_dns_enabled: true,
  },
} as unknown as TerraformResource;

describe('APIGW-005 (Terraform) - REQ-01: REST API with no endpoint-type configuration', () => {
  // Primary behavior owned by this requirement: no endpoint_configuration block
  // means the API defaults to a public (edge-optimized) endpoint and is flagged.
  it('flags a REST API declared with no endpoint-type configuration at all', () => {
    const restApi: TerraformResource = {
      type: 'aws_api_gateway_rest_api',
      name: 'orders',
      address: 'aws_api_gateway_rest_api.orders',
      values: {
        name: 'orders-api',
        description: 'No endpoint_configuration specified',
      },
    } as unknown as TerraformResource;

    const result = scan(restApi, [restApi, vpcEndpoint]);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('APIGW-005');
    expect(result!.resourceName).toBe('aws_api_gateway_rest_api.orders');
    expect(result!.resourceType).toBe('aws_api_gateway_rest_api');
  });

  // Opposite outcome: the nearest input that flips the verdict - the same API
  // with a PRIVATE endpoint type wired (reference form) to a properly
  // configured execute-api VPC endpoint.
  it('does not flag an otherwise identical REST API configured as a PRIVATE endpoint behind a properly configured VPC endpoint', () => {
    const restApi: TerraformResource = {
      type: 'aws_api_gateway_rest_api',
      name: 'orders',
      address: 'aws_api_gateway_rest_api.orders',
      values: {
        name: 'orders-api',
        description: 'No endpoint_configuration specified',
        endpoint_configuration: [
          {
            types: ['PRIVATE'],
            // Reference form: user wrote aws_vpc_endpoint.api.id in HCL.
            vpc_endpoint_ids: ['aws_vpc_endpoint.api'],
          },
        ],
      },
    } as unknown as TerraformResource;

    const result = scan(restApi, [restApi, vpcEndpoint]);

    expect(result).toBeNull();
  });
});
