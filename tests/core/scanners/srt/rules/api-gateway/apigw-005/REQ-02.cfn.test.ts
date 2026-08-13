import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw005CfnAdapterFactory();

const COMPLIANT_VPC_ENDPOINT: Resource = {
  Type: 'AWS::EC2::VPCEndpoint',
  Properties: {
    VpcId: 'vpc-123',
    ServiceName: 'com.amazonaws.us-east-1.execute-api',
    VpcEndpointType: 'Interface',
    SubnetIds: ['subnet-1', 'subnet-2'],
    SecurityGroupIds: ['sg-1'],
    PrivateDnsEnabled: true,
  },
} as unknown as Resource;

function buildTemplate(endpointConfiguration: Record<string, unknown>): Template {
  return {
    Resources: {
      RestApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'my-api',
          EndpointConfiguration: endpointConfiguration,
        },
      },
      ApiVpcEndpoint: COMPLIANT_VPC_ENDPOINT,
    },
  } as unknown as Template;
}

function run(endpointConfiguration: Record<string, unknown>) {
  const template = buildTemplate(endpointConfiguration);
  const resource = (template.Resources as Record<string, Resource>)['RestApi'] as Resource;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'RestApi',
  };
  return apigw005Control.run(factory.bind(context) as never, context);
}

describe('APIGW-005 REQ-02 (CloudFormation): explicitly public endpoint type', () => {
  // Primary behavior owned by this requirement: REGIONAL / EDGE endpoint types must be flagged.
  it('flags a REST API whose endpoint type is REGIONAL', () => {
    const result = run({ Types: ['REGIONAL'] });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe('RestApi');
    expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
    expect(result?.issue).toContain('publicly reachable endpoint type');
  });

  it('flags a REST API whose endpoint type is EDGE', () => {
    const result = run({ Types: ['EDGE'] });

    expect(result).not.toBeNull();
    expect(result?.issue).toContain('publicly reachable endpoint type');
  });

  it('flags a REST API that lists a public endpoint type even when a compliant VPC endpoint is attached', () => {
    const result = run({ Types: ['REGIONAL'], VpcEndpointIds: ['ApiVpcEndpoint'] });

    expect(result).not.toBeNull();
    expect(result?.issue).toContain('publicly reachable endpoint type');
  });

  // Opposite outcome: the nearest input that flips the verdict — same fixture, PRIVATE type instead of public.
  it('does not flag a REST API whose endpoint type is PRIVATE with a compliant VPC endpoint', () => {
    const result = run({ Types: ['PRIVATE'], VpcEndpointIds: ['ApiVpcEndpoint'] });

    expect(result).toBeNull();
  });
});
