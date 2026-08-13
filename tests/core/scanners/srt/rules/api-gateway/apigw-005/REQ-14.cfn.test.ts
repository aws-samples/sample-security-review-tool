import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-14 (APIGW-005): A private REST API whose interface VPC endpoint service name is
 * dynamically composed (e.g. "com.amazonaws.${AWS::Region}.execute-api", which
 * preprocessing collapses to "com.amazonaws.us-east-1.execute-api") still unambiguously
 * designates the API Gateway execute-api service, so the private access path exists.
 */

const factory = new Apigw005CfnAdapterFactory();

function buildTemplate(serviceName: unknown): Template {
  return {
    Resources: {
      PrivateApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'private-api',
          EndpointConfiguration: {
            Types: ['PRIVATE'],
            // !Ref ApiGatewayVpcEndpoint collapses to the logical ID string
            VpcEndpointIds: ['ApiGatewayVpcEndpoint'],
          },
        },
      },
      ApiGatewayVpcEndpoint: {
        Type: 'AWS::EC2::VPCEndpoint',
        Properties: {
          VpcId: 'Vpc',
          VpcEndpointType: 'Interface',
          // Authored as !Sub 'com.amazonaws.${AWS::Region}.<service>'
          ServiceName: serviceName,
          SubnetIds: ['subnet-11111111', 'subnet-22222222'],
          SecurityGroupIds: ['sg-11111111'],
          PrivateDnsEnabled: true,
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template): ScanResult | null {
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: template.Resources!['PrivateApi'],
    logicalId: 'PrivateApi',
  };
  const adapter = factory.bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 REQ-14 (CloudFormation): dynamically composed execute-api service name', () => {
  it('passes when the composed service name resolves to the API Gateway execute-api service and the endpoint is fully configured', () => {
    const result = run(buildTemplate('com.amazonaws.us-east-1.execute-api'));

    expect(result).toBeNull();
  });

  // Opposite outcome: same dynamic composition shape, but the composed value designates
  // a different service, so no execute-api private access path exists.
  it('flags when the composed service name resolves to a service other than execute-api', () => {
    const result = run(buildTemplate('com.amazonaws.us-east-1.s3'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe('PrivateApi');
  });
});
