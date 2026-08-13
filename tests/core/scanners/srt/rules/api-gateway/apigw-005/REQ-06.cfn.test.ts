import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw005CfnAdapterFactory();

/**
 * Builds a template with a PRIVATE REST API wired to a single interface VPC endpoint.
 * `serviceName` decides whether that endpoint serves API Gateway's execute-api
 * service or some unrelated AWS service.
 */
function buildTemplate(serviceName: string): Template {
  return {
    Resources: {
      PrivateApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'private-api',
          EndpointConfiguration: {
            Types: ['PRIVATE'],
            // !Ref OnlyInterfaceEndpoint resolves to the logical id string.
            VpcEndpointIds: ['OnlyInterfaceEndpoint'],
          },
        },
      },
      OnlyInterfaceEndpoint: {
        Type: 'AWS::EC2::VPCEndpoint',
        Properties: {
          VpcId: 'vpc-1234567890abcdef0',
          VpcEndpointType: 'Interface',
          ServiceName: serviceName,
          SubnetIds: ['subnet-aaa111', 'subnet-bbb222'],
          SecurityGroupIds: ['sg-aaa111'],
          PrivateDnsEnabled: true,
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template): ScanResult | null {
  const resource = (template.Resources ?? {})['PrivateApi'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'PrivateApi',
  };
  const adapter = factory.bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 REQ-06 (CloudFormation): private API whose only interface VPC endpoint serves another service', () => {
  // Primary behaviour owned by this requirement: an execute-api endpoint is required.
  it('flags a PRIVATE REST API when the only interface VPC endpoint is for a non-execute-api service', () => {
    const result = run(buildTemplate('com.amazonaws.us-east-1.secretsmanager'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
    expect(result?.resourceName).toBe('PrivateApi');
  });

  // Nearest input that flips the verdict: same template, endpoint service is execute-api.
  it('does not flag when that same VPC endpoint serves the API Gateway execute-api service', () => {
    const result = run(buildTemplate('com.amazonaws.us-east-1.execute-api'));

    expect(result).toBeNull();
  });
});
