import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STACK_NAME = 'apigw-005-stack';
const REST_API_ID = 'PrivateRestApi';
const VPC_ENDPOINT_ID = 'ExecuteApiVpcEndpoint';

const factory = new Apigw005CfnAdapterFactory();

/**
 * Builds a template where the REST API is PRIVATE and references an interface
 * VPC endpoint for execute-api with private DNS enabled. The subnet configuration
 * of that endpoint is the only thing that varies between cases.
 *
 * `!Ref ExecuteApiVpcEndpoint` resolves to the logical id string after preprocessing.
 */
function buildTemplate(vpcEndpointSubnets: unknown): Template {
  const vpcEndpointProperties: Record<string, unknown> = {
    ServiceName: 'com.amazonaws.us-east-1.execute-api',
    VpcEndpointType: 'Interface',
    VpcId: 'vpc-0123456789abcdef0',
    SecurityGroupIds: ['sg-0123456789abcdef0'],
    PrivateDnsEnabled: true,
  };
  if (vpcEndpointSubnets !== undefined) {
    vpcEndpointProperties['SubnetIds'] = vpcEndpointSubnets;
  }

  return {
    Resources: {
      [REST_API_ID]: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'private-api',
          EndpointConfiguration: {
            Types: ['PRIVATE'],
            VpcEndpointIds: [VPC_ENDPOINT_ID],
          },
        },
      },
      [VPC_ENDPOINT_ID]: {
        Type: 'AWS::EC2::VPCEndpoint',
        Properties: vpcEndpointProperties,
      },
    },
  } as unknown as Template;
}

function run(template: Template): ScanResult | null {
  const resource = (template.Resources ?? {})[REST_API_ID];
  const context: CfnContext = {
    stackName: STACK_NAME,
    template,
    resource,
    logicalId: REST_API_ID,
  };
  const adapter = factory.bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 REQ-09 (CloudFormation): private API whose execute-api VPC endpoint declares no subnets', () => {
  // Primary behavior owned by this requirement: an interface endpoint with no
  // subnets provides no in-VPC network path, so the wiring is incomplete.
  it('flags a private API when the referenced VPC endpoint has an empty subnet list', () => {
    const result = run(buildTemplate([]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe(REST_API_ID);
    expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
  });

  it('flags a private API when the referenced VPC endpoint declares no SubnetIds property at all', () => {
    const result = run(buildTemplate(undefined));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });

  // Opposite outcome: identical configuration except the endpoint declares subnets,
  // which is the only thing this requirement turns on.
  it('does not flag when the same VPC endpoint declares at least one subnet id', () => {
    const result = run(buildTemplate(['subnet-0123456789abcdef0']));

    expect(result).toBeNull();
  });
});
