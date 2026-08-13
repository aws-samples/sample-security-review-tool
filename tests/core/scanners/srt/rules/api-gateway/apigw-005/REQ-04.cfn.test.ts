import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const API_LOGICAL_ID = 'PrivateRestApi';
const ENDPOINT_LOGICAL_ID = 'ExecuteApiVpcEndpoint';

interface VpcEndpointOverrides {
  readonly ServiceName?: unknown;
  readonly SubnetIds?: unknown;
  readonly SecurityGroupIds?: unknown;
  readonly PrivateDnsEnabled?: unknown;
}

function buildTemplate(endpointOverrides: VpcEndpointOverrides = {}): Template {
  return {
    Resources: {
      [API_LOGICAL_ID]: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'private-api',
          EndpointConfiguration: {
            Types: ['PRIVATE'],
            // !Ref ExecuteApiVpcEndpoint resolves to the logical ID string
            VpcEndpointIds: [ENDPOINT_LOGICAL_ID],
          },
        },
      },
      [ENDPOINT_LOGICAL_ID]: {
        Type: 'AWS::EC2::VPCEndpoint',
        Properties: {
          VpcId: 'AppVpc',
          VpcEndpointType: 'Interface',
          ServiceName: 'com.amazonaws.us-east-1.execute-api',
          SubnetIds: ['subnet-aaa1', 'subnet-bbb2'],
          SecurityGroupIds: ['sg-1234abcd'],
          PrivateDnsEnabled: true,
          ...endpointOverrides,
        },
      },
    },
  } as unknown as Template;
}

function runControl(template: Template) {
  const resource = (template.Resources ?? {})[API_LOGICAL_ID];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: API_LOGICAL_ID,
  };
  const adapter = new Apigw005CfnAdapterFactory().bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 CloudFormation - private API fronted by a fully configured execute-api interface endpoint', () => {
  // Primary behavior owned by this requirement (REQ-04): the fully compliant pattern must pass.
  it('returns no finding when the private API references an execute-api VPC endpoint with subnets, security groups and private DNS enabled', () => {
    expect(runControl(buildTemplate())).toBeNull();
  });

  it('reports the endpoint types and compliant VPC endpoint through the adapter', () => {
    const template = buildTemplate();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: (template.Resources ?? {})[API_LOGICAL_ID],
      logicalId: API_LOGICAL_ID,
    };
    const adapter = new Apigw005CfnAdapterFactory().bind(context) as Apigw005Adapter;

    expect(adapter.getEndpointTypes()).toEqual(['PRIVATE']);
    expect(adapter.hasCompliantVpcEndpoint()).toBe(true);
  });

  // Opposite outcome: same fixture, only private DNS flipped off, so coverage is not properly configured.
  it('returns a finding when the referenced execute-api VPC endpoint has private DNS disabled', () => {
    const result = runControl(buildTemplate({ PrivateDnsEnabled: false }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe(API_LOGICAL_ID);
  });
});
