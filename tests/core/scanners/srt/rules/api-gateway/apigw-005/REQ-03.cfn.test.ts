import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw005CfnAdapterFactory();

function buildContext(resources: Record<string, unknown>, logicalId: string): CfnContext {
  const template = { Resources: resources } as unknown as Template;
  return {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, Resource>)[logicalId]!,
    logicalId,
  };
}

function evaluate(resources: Record<string, unknown>, logicalId: string): ScanResult | null {
  const context = buildContext(resources, logicalId);
  const adapter = factory.bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

const compliantVpcEndpoint = {
  Type: 'AWS::EC2::VPCEndpoint',
  Properties: {
    ServiceName: 'com.amazonaws.us-east-1.execute-api',
    VpcEndpointType: 'Interface',
    SubnetIds: ['subnet-1'],
    SecurityGroupIds: ['sg-1'],
    PrivateDnsEnabled: true,
  },
};

describe('APIGW-005 (CloudFormation) - endpoint-type list present but empty', () => {
  // Primary behaviour owned by this requirement: an empty Types list asserts no
  // private configuration, so the API falls back to the public default endpoint type.
  it('flags a REST API whose EndpointConfiguration.Types is an empty list', () => {
    const result = evaluate({
      Api: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'my-api',
          EndpointConfiguration: {
            Types: [],
            VpcEndpointIds: ['Vpce'],
          },
        },
      },
      Vpce: compliantVpcEndpoint,
    }, 'Api');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe('Api');
    expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
  });

  // Opposite outcome: nearest input that flips the verdict - the same template with
  // PRIVATE present in the otherwise-empty list must not be flagged.
  it('does not flag a REST API whose Types list contains PRIVATE with a compliant VPC endpoint', () => {
    const result = evaluate({
      Api: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'my-api',
          EndpointConfiguration: {
            Types: ['PRIVATE'],
            VpcEndpointIds: ['Vpce'],
          },
        },
      },
      Vpce: compliantVpcEndpoint,
    }, 'Api');

    expect(result).toBeNull();
  });
});
