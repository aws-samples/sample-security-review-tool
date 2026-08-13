import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const API_LOGICAL_ID = 'PrivateRestApi';
const ENDPOINT_LOGICAL_ID = 'ExecuteApiEndpoint';

interface EndpointOptions {
  readonly privateDnsEnabled: boolean;
  readonly associated: boolean;
}

function buildTemplate(options: EndpointOptions): Template {
  const api = {
    Type: 'AWS::ApiGateway::RestApi',
    Properties: {
      Name: 'private-api',
      EndpointConfiguration: {
        Types: ['PRIVATE'],
        // A Ref/GetAtt to the VPC endpoint collapses to its logical ID string.
        VpcEndpointIds: options.associated ? [ENDPOINT_LOGICAL_ID] : [],
      },
    },
  } as unknown as Resource;

  const vpcEndpoint = {
    Type: 'AWS::EC2::VPCEndpoint',
    Properties: {
      ServiceName: 'com.amazonaws.us-east-1.execute-api',
      VpcEndpointType: 'Interface',
      VpcId: 'vpc-12345678',
      SubnetIds: ['subnet-11111111', 'subnet-22222222'],
      SecurityGroupIds: ['sg-11111111'],
      PrivateDnsEnabled: options.privateDnsEnabled,
    },
  } as unknown as Resource;

  return {
    Resources: {
      [API_LOGICAL_ID]: api,
      [ENDPOINT_LOGICAL_ID]: vpcEndpoint,
    },
  } as unknown as Template;
}

function runControl(template: Template): ScanResult | null {
  const resource = (template.Resources ?? {})[API_LOGICAL_ID] as Resource;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: API_LOGICAL_ID,
  };
  const adapter = new Apigw005CfnAdapterFactory().bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 REQ-07 (CloudFormation): private API with an execute-api endpoint whose private DNS is disabled and which is not associated', () => {
  it('flags the private REST API when the execute-api VPC endpoint has private DNS disabled and is not associated with the API', () => {
    const result = runControl(buildTemplate({ privateDnsEnabled: false, associated: false }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe(API_LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
  });

  it('flags the private REST API when the associated execute-api VPC endpoint still has private DNS explicitly disabled', () => {
    // Isolates the private-DNS-enabled requirement: association alone is not enough.
    const result = runControl(buildTemplate({ privateDnsEnabled: false, associated: true }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });

  // Opposite outcome: the nearest compliant input — same private API and same
  // execute-api endpoint with subnets and security groups, but private DNS enabled
  // and the endpoint associated with the assessed API.
  it('does not flag the private REST API when the associated execute-api VPC endpoint has private DNS enabled', () => {
    const result = runControl(buildTemplate({ privateDnsEnabled: true, associated: true }));

    expect(result).toBeNull();
  });
});
