import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const ENDPOINT_ADDRESS = 'aws_vpc_endpoint.execute_api';
const ENDPOINT_ID = 'vpce-0123456789abcdef0';

function vpcEndpoint(overrides: Record<string, unknown> = {}): TerraformResource {
  return {
    type: 'aws_vpc_endpoint',
    name: 'execute_api',
    address: ENDPOINT_ADDRESS,
    values: {
      id: ENDPOINT_ID,
      vpc_id: 'aws_vpc.app',
      vpc_endpoint_type: 'Interface',
      service_name: 'com.amazonaws.us-east-1.execute-api',
      subnet_ids: ['subnet-aaa1', 'subnet-bbb2'],
      security_group_ids: ['sg-1234abcd'],
      private_dns_enabled: true,
      ...overrides,
    },
  } as unknown as TerraformResource;
}

function restApi(vpcEndpointIds: unknown[]): TerraformResource {
  return {
    type: 'aws_api_gateway_rest_api',
    name: 'private_api',
    address: 'aws_api_gateway_rest_api.private_api',
    values: {
      name: 'private-api',
      endpoint_configuration: [
        {
          types: ['PRIVATE'],
          vpc_endpoint_ids: vpcEndpointIds,
        },
      ],
    },
  } as unknown as TerraformResource;
}

function runControl(api: TerraformResource, endpoint: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: api,
    allResources: [api, endpoint],
  };
  const adapter = new Apigw005TfAdapterFactory().bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 Terraform - private API fronted by a fully configured execute-api interface endpoint', () => {
  // Primary behavior owned by this requirement (REQ-04): the fully compliant pattern must pass.
  it('returns no finding when the private API references the execute-api VPC endpoint by address (reference form)', () => {
    expect(runControl(restApi([ENDPOINT_ADDRESS]), vpcEndpoint())).toBeNull();
  });

  it('returns no finding when the private API references the execute-api VPC endpoint by literal id', () => {
    expect(runControl(restApi([ENDPOINT_ID]), vpcEndpoint())).toBeNull();
  });

  it('reports the endpoint types and compliant VPC endpoint through the adapter', () => {
    const api = restApi([ENDPOINT_ADDRESS]);
    const context: TfContext = {
      projectName: 'test-project',
      resource: api,
      allResources: [api, vpcEndpoint()],
    };
    const adapter = new Apigw005TfAdapterFactory().bind(context) as Apigw005Adapter;

    expect(adapter.getEndpointTypes()).toEqual(['PRIVATE']);
    expect(adapter.hasCompliantVpcEndpoint()).toBe(true);
  });

  // Opposite outcome: same fixture, only private DNS flipped off, so coverage is not properly configured.
  it('returns a finding when the referenced execute-api VPC endpoint has private DNS disabled', () => {
    const result = runControl(restApi([ENDPOINT_ADDRESS]), vpcEndpoint({ private_dns_enabled: false }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe('aws_api_gateway_rest_api.private_api');
  });
});
