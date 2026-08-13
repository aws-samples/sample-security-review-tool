import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (APIGW-005): A PRIVATE REST API must also be reachable through an interface
 * VPC endpoint for the API Gateway execute-api service. When the plan contains no
 * such VPC endpoint at all, the private access path is not provisioned and the API
 * must be flagged.
 */

const factory = new Apigw005TfAdapterFactory();

function privateApi(vpcEndpointIds?: string[]): TerraformResource {
  const endpointConfiguration: Record<string, unknown> = { types: ['PRIVATE'] };
  if (vpcEndpointIds) endpointConfiguration['vpc_endpoint_ids'] = vpcEndpointIds;
  return {
    type: 'aws_api_gateway_rest_api',
    name: 'private_api',
    address: 'aws_api_gateway_rest_api.private_api',
    values: {
      name: 'private-api',
      endpoint_configuration: [endpointConfiguration],
    },
  } as unknown as TerraformResource;
}

const compliantVpcEndpoint = {
  type: 'aws_vpc_endpoint',
  name: 'execute_api',
  address: 'aws_vpc_endpoint.execute_api',
  values: {
    service_name: 'com.amazonaws.us-east-1.execute-api',
    vpc_endpoint_type: 'Interface',
    subnet_ids: ['subnet-aaa', 'subnet-bbb'],
    security_group_ids: ['sg-aaa'],
    private_dns_enabled: true,
  },
} as unknown as TerraformResource;

function run(api: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: api,
    allResources,
  };
  return apigw005Control.run(factory.bind(context), context);
}

describe('APIGW-005 REQ-05 (Terraform): private API with no execute-api VPC endpoint in the plan', () => {
  it('flags a PRIVATE rest api when the plan declares no aws_vpc_endpoint at all', () => {
    const api = privateApi();
    const result = run(api, [api]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe('aws_api_gateway_rest_api.private_api');
    expect(result?.resourceType).toBe('aws_api_gateway_rest_api');
  });

  it('flags a PRIVATE rest api that references a vpc endpoint address absent from the plan', () => {
    // Reference form: HCL wrote vpc_endpoint_ids = [aws_vpc_endpoint.execute_api.id]
    const api = privateApi(['aws_vpc_endpoint.execute_api']);
    const result = run(api, [api]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });

  // Opposite outcome: the nearest input that flips the verdict — identical private API,
  // but the referenced execute-api interface VPC endpoint exists and is fully configured.
  it('does not flag the same PRIVATE rest api when the referenced compliant execute-api VPC endpoint exists', () => {
    const api = privateApi(['aws_vpc_endpoint.execute_api']);
    const result = run(api, [api, compliantVpcEndpoint]);

    expect(result).toBeNull();
  });
});
