import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (APIGW-005): A PRIVATE REST API must also be reachable through an interface
 * VPC endpoint for the API Gateway execute-api service. When the template contains no
 * such VPC endpoint at all, the private access path is not provisioned and the API
 * must be flagged.
 */

const factory = new Apigw005CfnAdapterFactory();

function buildContext(resources: Record<string, unknown>, logicalId = 'PrivateApi'): CfnContext {
  const template = { Resources: resources } as unknown as Template;
  return {
    stackName: 'test-stack',
    template,
    resource: resources[logicalId] as Resource,
    logicalId,
  };
}

function run(resources: Record<string, unknown>, logicalId = 'PrivateApi') {
  const context = buildContext(resources, logicalId);
  return apigw005Control.run(factory.bind(context), context);
}

const compliantVpcEndpoint = {
  Type: 'AWS::EC2::VPCEndpoint',
  Properties: {
    VpcId: 'MyVpc',
    ServiceName: 'com.amazonaws.us-east-1.execute-api',
    VpcEndpointType: 'Interface',
    SubnetIds: ['subnet-aaa', 'subnet-bbb'],
    SecurityGroupIds: ['sg-aaa'],
    PrivateDnsEnabled: true,
  },
};

describe('APIGW-005 REQ-05 (CloudFormation): private API with no execute-api VPC endpoint in the template', () => {
  it('flags a PRIVATE REST API when the template declares no VPC endpoint at all', () => {
    const result = run({
      PrivateApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'private-api',
          EndpointConfiguration: { Types: ['PRIVATE'] },
        },
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe('PrivateApi');
    expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
  });

  it('flags a PRIVATE REST API that lists a VPC endpoint id which exists nowhere in the template', () => {
    const result = run({
      PrivateApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'private-api',
          EndpointConfiguration: {
            Types: ['PRIVATE'],
            VpcEndpointIds: ['ApiGatewayVpcEndpoint'],
          },
        },
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });

  // Opposite outcome: the nearest input that flips the verdict — identical private API,
  // but the execute-api interface VPC endpoint is present and fully configured.
  it('does not flag the same PRIVATE REST API when a compliant execute-api VPC endpoint exists', () => {
    const result = run({
      PrivateApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'private-api',
          EndpointConfiguration: {
            Types: ['PRIVATE'],
            VpcEndpointIds: ['ApiGatewayVpcEndpoint'],
          },
        },
      },
      ApiGatewayVpcEndpoint: compliantVpcEndpoint,
    });

    expect(result).toBeNull();
  });
});
