import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STACK_NAME = 'test-stack';
const REST_API_ID = 'PrivateRestApi';
const VPC_ENDPOINT_ID = 'ExecuteApiEndpoint';

function buildTemplate(vpcEndpointProperties: Record<string, unknown>): Template {
  return {
    Resources: {
      [REST_API_ID]: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'private-api',
          EndpointConfiguration: {
            Types: ['PRIVATE'],
            // !Ref ExecuteApiEndpoint resolves to the logical id string
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
  const adapter = new Apigw005CfnAdapterFactory().bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 (CloudFormation) - private API with a VPC endpoint that declares no security groups', () => {
  // Primary behaviour owned by this requirement: security group ids are mandatory on the execute-api VPC endpoint.
  it('flags a private REST API whose execute-api VPC endpoint omits SecurityGroupIds', () => {
    const result = run(buildTemplate({
      ServiceName: 'com.amazonaws.us-east-1.execute-api',
      VpcId: 'vpc-123',
      VpcEndpointType: 'Interface',
      SubnetIds: ['subnet-aaa', 'subnet-bbb'],
      PrivateDnsEnabled: true,
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe(REST_API_ID);
  });

  it('flags a private REST API whose execute-api VPC endpoint declares an empty SecurityGroupIds list', () => {
    const result = run(buildTemplate({
      ServiceName: 'com.amazonaws.us-east-1.execute-api',
      VpcId: 'vpc-123',
      VpcEndpointType: 'Interface',
      SubnetIds: ['subnet-aaa'],
      SecurityGroupIds: [],
      PrivateDnsEnabled: true,
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });

  // Opposite outcome: identical fixture except the endpoint declares security group ids.
  it('does not flag when the same execute-api VPC endpoint declares security group ids', () => {
    const result = run(buildTemplate({
      ServiceName: 'com.amazonaws.us-east-1.execute-api',
      VpcId: 'vpc-123',
      VpcEndpointType: 'Interface',
      SubnetIds: ['subnet-aaa', 'subnet-bbb'],
      SecurityGroupIds: ['sg-123'],
      PrivateDnsEnabled: true,
    }));

    expect(result).toBeNull();
  });
});
