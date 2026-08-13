import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw005TfAdapterFactory();

const compliantVpcEndpoint: TerraformResource = {
  type: 'aws_vpc_endpoint',
  name: 'api',
  address: 'aws_vpc_endpoint.api',
  values: {
    service_name: 'com.amazonaws.us-east-1.execute-api',
    vpc_endpoint_type: 'Interface',
    subnet_ids: ['subnet-1'],
    security_group_ids: ['sg-1'],
    private_dns_enabled: true,
  },
} as unknown as TerraformResource;

function evaluate(api: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: api,
    allResources: [api, compliantVpcEndpoint],
  };
  const adapter = factory.bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

function restApi(types: string[]): TerraformResource {
  return {
    type: 'aws_api_gateway_rest_api',
    name: 'api',
    address: 'aws_api_gateway_rest_api.api',
    values: {
      name: 'my-api',
      endpoint_configuration: [{
        types,
        // reference form - user wrote aws_vpc_endpoint.api.id in HCL
        vpc_endpoint_ids: ['aws_vpc_endpoint.api'],
      }],
    },
  } as unknown as TerraformResource;
}

describe('APIGW-005 (Terraform) - endpoint-type list present but empty', () => {
  // Primary behaviour owned by this requirement: an empty types list asserts no
  // private configuration, so the API falls back to the public default endpoint type.
  it('flags a REST API whose endpoint_configuration.types is an empty list', () => {
    const result = evaluate(restApi([]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe('aws_api_gateway_rest_api.api');
    expect(result?.resourceType).toBe('aws_api_gateway_rest_api');
  });

  // Opposite outcome: nearest input that flips the verdict - the same plan with
  // PRIVATE present in the otherwise-empty list must not be flagged.
  it('does not flag a REST API whose types list contains PRIVATE with a compliant VPC endpoint', () => {
    const result = evaluate(restApi(['PRIVATE']));

    expect(result).toBeNull();
  });
});
