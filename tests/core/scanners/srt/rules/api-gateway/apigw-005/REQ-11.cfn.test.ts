import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const REST_API_ID = 'PrivateRestApi';

/**
 * Builds a template with a PRIVATE REST API that lists several interface VPC endpoints:
 * - a fully configured execute-api endpoint (the one that provides private access),
 * - an execute-api endpoint missing private DNS,
 * - a fully configured endpoint for another service (S3).
 */
function buildTemplate(options: { privateDnsOnApiGatewayEndpoint: boolean }): Template {
  return {
    Resources: {
      [REST_API_ID]: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'private-api',
          EndpointConfiguration: {
            Types: ['PRIVATE'],
            // Fn::Ref/GetAtt collapse to logical IDs during preprocessing.
            VpcEndpointIds: ['IncompleteApiGatewayEndpoint', 'S3Endpoint', 'ApiGatewayEndpoint'],
          },
        },
      },
      ApiGatewayEndpoint: {
        Type: 'AWS::EC2::VPCEndpoint',
        Properties: {
          VpcEndpointType: 'Interface',
          ServiceName: 'com.amazonaws.us-east-1.execute-api',
          VpcId: 'Vpc',
          SubnetIds: ['SubnetA', 'SubnetB'],
          SecurityGroupIds: ['ApiEndpointSecurityGroup'],
          PrivateDnsEnabled: options.privateDnsOnApiGatewayEndpoint,
        },
      },
      IncompleteApiGatewayEndpoint: {
        Type: 'AWS::EC2::VPCEndpoint',
        Properties: {
          VpcEndpointType: 'Interface',
          ServiceName: 'com.amazonaws.us-east-1.execute-api',
          VpcId: 'Vpc',
          // No subnets, no security groups, private DNS disabled.
          PrivateDnsEnabled: false,
        },
      },
      S3Endpoint: {
        Type: 'AWS::EC2::VPCEndpoint',
        Properties: {
          VpcEndpointType: 'Interface',
          ServiceName: 'com.amazonaws.us-east-1.s3',
          VpcId: 'Vpc',
          SubnetIds: ['SubnetA'],
          SecurityGroupIds: ['S3EndpointSecurityGroup'],
          PrivateDnsEnabled: true,
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template): ScanResult | null {
  const resource = (template.Resources ?? {})[REST_API_ID];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: REST_API_ID,
  };
  const adapter = new Apigw005CfnAdapterFactory().bind(context);
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 (CloudFormation) - private API with a mix of VPC endpoints', () => {
  // Primary behavior owned by this requirement: one fully configured execute-api
  // interface endpoint is enough, even alongside incomplete or unrelated endpoints.
  it('does not report a finding when at least one execute-api endpoint is fully configured', () => {
    expect(run(buildTemplate({ privateDnsOnApiGatewayEndpoint: true }))).toBeNull();
  });

  // Opposite outcome: identical template except the only complete execute-api
  // endpoint has private DNS disabled, so no endpoint provides private access.
  it('reports a finding when no execute-api endpoint is fully configured', () => {
    const result = run(buildTemplate({ privateDnsOnApiGatewayEndpoint: false }));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe(REST_API_ID);
  });
});
