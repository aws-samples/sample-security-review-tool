import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw005TfAdapterFactory();

const compliantVpcEndpoint: TerraformResource = {
  type: 'aws_vpc_endpoint',
  name: 'api',
  address: 'aws_vpc_endpoint.api',
  values: {
    service_name: 'com.amazonaws.us-east-1.execute-api',
    vpc_endpoint_type: 'Interface',
    subnet_ids: ['subnet-1', 'subnet-2'],
    security_group_ids: ['sg-1'],
    private_dns_enabled: true,
  },
} as unknown as TerraformResource;

function restApi(endpointConfiguration: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_api_gateway_rest_api',
    name: 'api',
    address: 'aws_api_gateway_rest_api.api',
    values: {
      name: 'my-api',
      endpoint_configuration: [endpointConfiguration],
    },
  } as unknown as TerraformResource;
}

function run(endpointConfiguration: Record<string, unknown>) {
  const resource = restApi(endpointConfiguration);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource, compliantVpcEndpoint],
  };
  return apigw005Control.run(factory.bind(context) as never, context);
}

describe('APIGW-005 REQ-02 (Terraform): explicitly public endpoint type', () => {
  // Primary behavior owned by this requirement: REGIONAL / EDGE endpoint types must be flagged.
  it('flags a REST API whose endpoint type is REGIONAL', () => {
    const result = run({ types: ['REGIONAL'] });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe('aws_api_gateway_rest_api.api');
    expect(result?.resourceType).toBe('aws_api_gateway_rest_api');
    expect(result?.issue).toContain('publicly reachable endpoint type');
  });

  it('flags a REST API whose endpoint type is EDGE', () => {
    const result = run({ types: ['EDGE'] });

    expect(result).not.toBeNull();
    expect(result?.issue).toContain('publicly reachable endpoint type');
  });

  it('flags a REST API with a public endpoint type even when it references a compliant VPC endpoint', () => {
    // reference form — HCL wrote aws_vpc_endpoint.api.id, collapsed to the address
    const result = run({ types: ['REGIONAL'], vpc_endpoint_ids: ['aws_vpc_endpoint.api'] });

    expect(result).not.toBeNull();
    expect(result?.issue).toContain('publicly reachable endpoint type');
  });

  // Opposite outcome: the nearest input that flips the verdict — same fixture, PRIVATE type instead of public.
  it('does not flag a REST API whose endpoint type is PRIVATE with a referenced compliant VPC endpoint', () => {
    const result = run({ types: ['PRIVATE'], vpc_endpoint_ids: ['aws_vpc_endpoint.api'] });

    expect(result).toBeNull();
  });
});
