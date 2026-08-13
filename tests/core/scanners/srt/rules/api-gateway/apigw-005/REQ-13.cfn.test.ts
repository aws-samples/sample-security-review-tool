import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STACK_NAME = 'test-stack';
const factory = new Apigw005CfnAdapterFactory();

function scan(resources: Record<string, unknown>, logicalId = 'RestApi'): ScanResult | null {
  const template = { Resources: resources } as unknown as Template;
  const context: CfnContext = {
    stackName: STACK_NAME,
    template,
    resource: resources[logicalId] as Resource,
    logicalId,
  };
  const adapter = factory.bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

function vpcEndpoint(privateDnsEnabled: unknown): Record<string, unknown> {
  return {
    Type: 'AWS::EC2::VPCEndpoint',
    Properties: {
      ServiceName: 'com.amazonaws.us-east-1.execute-api',
      VpcEndpointType: 'Interface',
      VpcId: 'vpc-0123456789abcdef0',
      SubnetIds: ['subnet-aaa', 'subnet-bbb'],
      SecurityGroupIds: ['sg-aaa'],
      PrivateDnsEnabled: privateDnsEnabled,
    },
  };
}

function restApi(types: unknown, vpcEndpointIds: unknown[] = ['ApiVpcEndpoint']): Record<string, unknown> {
  return {
    Type: 'AWS::ApiGateway::RestApi',
    Properties: {
      Name: 'private-api',
      EndpointConfiguration: {
        Types: types,
        VpcEndpointIds: vpcEndpointIds,
      },
    },
  };
}

describe('APIGW-005 (CloudFormation) - unresolvable deciding value passes [REQ-13]', () => {
  it('returns no finding when the endpoint type is decided by an unresolved Fn::If', () => {
    const result = scan({
      RestApi: restApi({ 'Fn::If': ['IsPrivate', ['PRIVATE'], ['REGIONAL']] }),
      ApiVpcEndpoint: vpcEndpoint(true),
    });

    expect(result).toBeNull();
  });

  it('returns no finding when the whole endpoint configuration block is an unresolved Fn::If', () => {
    const result = scan({
      RestApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'private-api',
          EndpointConfiguration: {
            'Fn::If': [
              'IsPrivateApi',
              { Types: ['PRIVATE'], VpcEndpointIds: ['ApiVpcEndpoint'] },
              { Types: ['REGIONAL'] },
            ],
          },
        },
      },
      ApiVpcEndpoint: vpcEndpoint(true),
    });

    expect(result).toBeNull();
  });

  it('returns no finding when the endpoint type comes from an unresolved Fn::ImportValue', () => {
    const result = scan({
      RestApi: restApi([{ 'Fn::ImportValue': 'SharedEndpointType' }]),
      ApiVpcEndpoint: vpcEndpoint(true),
    });

    expect(result).toBeNull();
  });

  it('returns no finding when private DNS on the execute-api VPC endpoint is an unresolved Fn::If', () => {
    const result = scan({
      RestApi: restApi(['PRIVATE']),
      ApiVpcEndpoint: vpcEndpoint({ 'Fn::If': ['EnablePrivateDns', true, false] }),
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: the deciding values ARE resolvable and non-compliant.
  // Primary behavior for these cases is owned by the public-endpoint-type and
  // missing-vpc-endpoint requirements; asserted here only to prove this file
  // discriminates rather than passing everything.
  it('returns a finding when the resolvable endpoint type is public (nearest flipping input)', () => {
    const result = scan({
      RestApi: restApi(['REGIONAL']),
      ApiVpcEndpoint: vpcEndpoint(true),
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });

  it('returns a finding when private DNS is resolvably disabled on the execute-api VPC endpoint', () => {
    const result = scan({
      RestApi: restApi(['PRIVATE']),
      ApiVpcEndpoint: vpcEndpoint(false),
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });
});
