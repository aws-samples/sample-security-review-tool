import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.tf.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (APIGW-005): A PRIVATE REST API wired to a properly configured execute-api
 * VPC endpoint must still be flagged when its resource policy denies or excludes
 * requests arriving through that VPC endpoint (or its VPC).
 */

const vpcEndpoint: TerraformResource = {
  type: 'aws_vpc_endpoint',
  name: 'api',
  address: 'aws_vpc_endpoint.api',
  values: {
    service_name: 'com.amazonaws.us-east-1.execute-api',
    vpc_endpoint_type: 'Interface',
    vpc_id: 'vpc-0123456789abcdef0',
    subnet_ids: ['subnet-aaa111', 'subnet-bbb222'],
    security_group_ids: ['sg-aaa111'],
    private_dns_enabled: true,
  },
} as unknown as TerraformResource;

function buildApi(policy: string): TerraformResource {
  return {
    type: 'aws_api_gateway_rest_api',
    name: 'private_api',
    address: 'aws_api_gateway_rest_api.private_api',
    values: {
      name: 'private-api',
      endpoint_configuration: [
        {
          types: ['PRIVATE'],
          // Reference form: vpc_endpoint_ids = [aws_vpc_endpoint.api.id]
          vpc_endpoint_ids: ['aws_vpc_endpoint.api'],
        },
      ],
      policy,
    },
  } as unknown as TerraformResource;
}

function run(policy: string): ScanResult | null {
  const api = buildApi(policy);
  const context: TfContext = {
    projectName: 'test-project',
    resource: api,
    allResources: [api, vpcEndpoint],
  };
  const adapter = new Apigw005TfAdapterFactory().bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 REQ-12 (Terraform): resource policy excludes the private access path', () => {
  it('flags a private API whose policy only allows a different, unrelated VPC endpoint', () => {
    const result = run(JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'execute-api:Invoke',
          Resource: 'execute-api:/*',
          Condition: { StringEquals: { 'aws:SourceVpce': 'vpce-unrelated0000000' } },
        },
      ],
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceType).toBe('aws_api_gateway_rest_api');
    expect(result?.resourceName).toBe('aws_api_gateway_rest_api.private_api');
  });

  it('flags a private API whose policy explicitly denies requests from the associated VPC endpoint', () => {
    const result = run(JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'execute-api:Invoke',
          Resource: 'execute-api:/*',
        },
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 'execute-api:Invoke',
          Resource: 'execute-api:/*',
          Condition: { StringEquals: { 'aws:SourceVpce': 'aws_vpc_endpoint.api' } },
        },
      ],
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });

  // Opposite outcome: identical configuration, but the policy allows the very VPC
  // endpoint that provides the private path — the private route works, so no finding.
  it('does not flag a private API whose policy allows the associated VPC endpoint', () => {
    const result = run(JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'execute-api:Invoke',
          Resource: 'execute-api:/*',
          Condition: { StringEquals: { 'aws:SourceVpce': 'aws_vpc_endpoint.api' } },
        },
      ],
    }));

    expect(result).toBeNull();
  });
});
