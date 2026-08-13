import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw005TfAdapterFactory();

function scan(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

function vpcEndpoint(privateDnsEnabled: unknown): TerraformResource {
  return {
    type: 'aws_vpc_endpoint',
    name: 'api',
    address: 'aws_vpc_endpoint.api',
    values: {
      service_name: 'com.amazonaws.us-east-1.execute-api',
      vpc_endpoint_type: 'Interface',
      vpc_id: 'vpc-0123456789abcdef0',
      subnet_ids: ['subnet-aaa', 'subnet-bbb'],
      security_group_ids: ['sg-aaa'],
      private_dns_enabled: privateDnsEnabled,
    },
  } as unknown as TerraformResource;
}

// Reference form: HCL wrote vpc_endpoint_ids = [aws_vpc_endpoint.api.id],
// which the plan reader collapses to the endpoint's address.
function restApi(types: unknown): TerraformResource {
  return {
    type: 'aws_api_gateway_rest_api',
    name: 'private_api',
    address: 'aws_api_gateway_rest_api.private_api',
    values: {
      name: 'private-api',
      endpoint_configuration: [{
        types,
        vpc_endpoint_ids: ['aws_vpc_endpoint.api'],
      }],
    },
  } as unknown as TerraformResource;
}

describe('APIGW-005 (Terraform) - unresolvable deciding value passes [REQ-13]', () => {
  it('returns no finding when the endpoint type is unknown at plan time (null)', () => {
    const endpoint = vpcEndpoint(true);
    const api = restApi(null);

    expect(scan(api, [api, endpoint])).toBeNull();
  });

  it('returns no finding when an endpoint type entry is unknown at plan time (null element)', () => {
    const endpoint = vpcEndpoint(true);
    const api = restApi([null]);

    expect(scan(api, [api, endpoint])).toBeNull();
  });

  it('returns no finding when private DNS on the execute-api VPC endpoint is unknown at plan time', () => {
    const endpoint = vpcEndpoint(null);
    const api = restApi(['PRIVATE']);

    expect(scan(api, [api, endpoint])).toBeNull();
  });

  // Opposite outcome: the deciding values ARE resolvable and non-compliant.
  // Primary behavior for these cases is owned by the public-endpoint-type and
  // missing-vpc-endpoint requirements; asserted here only to prove this file
  // discriminates rather than passing everything.
  it('returns a finding when the resolvable endpoint type is public (nearest flipping input)', () => {
    const endpoint = vpcEndpoint(true);
    const api = restApi(['REGIONAL']);

    const result = scan(api, [api, endpoint]);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });

  it('returns a finding when private DNS is resolvably disabled on the execute-api VPC endpoint', () => {
    const endpoint = vpcEndpoint(false);
    const api = restApi(['PRIVATE']);

    const result = scan(api, [api, endpoint]);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });
});
