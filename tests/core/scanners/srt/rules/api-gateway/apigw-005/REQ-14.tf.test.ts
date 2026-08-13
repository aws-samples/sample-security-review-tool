import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-14 (APIGW-005): A private REST API whose interface VPC endpoint service name is
 * dynamically composed (e.g. "com.amazonaws.${var.region}.execute-api" / data source
 * interpolation) still unambiguously designates the API Gateway execute-api service,
 * so the private access path exists and the rule passes.
 */

const factory = new Apigw005TfAdapterFactory();

function vpcEndpoint(serviceName: unknown): TerraformResource {
  return {
    type: 'aws_vpc_endpoint',
    name: 'api',
    address: 'aws_vpc_endpoint.api',
    values: {
      service_name: serviceName,
      vpc_endpoint_type: 'Interface',
      vpc_id: 'vpc-abc123',
      subnet_ids: ['subnet-11111111', 'subnet-22222222'],
      security_group_ids: ['sg-11111111'],
      private_dns_enabled: true,
    },
  } as unknown as TerraformResource;
}

function restApi(vpcEndpointReference: string): TerraformResource {
  return {
    type: 'aws_api_gateway_rest_api',
    name: 'private',
    address: 'aws_api_gateway_rest_api.private',
    values: {
      name: 'private-api',
      endpoint_configuration: [
        {
          types: ['PRIVATE'],
          vpc_endpoint_ids: [vpcEndpointReference],
        },
      ],
    },
  } as unknown as TerraformResource;
}

function run(api: TerraformResource, endpoint: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: api,
    allResources: [api, endpoint],
  };
  const adapter = factory.bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 REQ-14 (Terraform): dynamically composed execute-api service name', () => {
  it('passes when the composed service name resolves to execute-api and the endpoint is wired by reference', () => {
    // Reference form: vpc_endpoint_ids = [aws_vpc_endpoint.api.id]
    const endpoint = vpcEndpoint('com.amazonaws.us-east-1.execute-api');
    const result = run(restApi('aws_vpc_endpoint.api'), endpoint);

    expect(result).toBeNull();
  });

  it('passes when the composed service name resolves to execute-api and the endpoint is wired by literal id', () => {
    const endpoint = vpcEndpoint('com.amazonaws.us-east-1.execute-api');
    (endpoint as unknown as { values: Record<string, unknown> }).values['id'] = 'vpce-0123456789abcdef0';
    const result = run(restApi('vpce-0123456789abcdef0'), endpoint);

    expect(result).toBeNull();
  });

  // Opposite outcome: identical composition shape, but the composed value designates
  // a different service, so no execute-api private access path exists.
  it('flags when the composed service name resolves to a service other than execute-api', () => {
    const endpoint = vpcEndpoint('com.amazonaws.us-east-1.s3');
    const result = run(restApi('aws_vpc_endpoint.api'), endpoint);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe('aws_api_gateway_rest_api.private');
  });
});
