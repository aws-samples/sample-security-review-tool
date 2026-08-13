import { describe, expect, it } from 'vitest';

import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw005CfnAdapterFactory();

function scan(template: Template, logicalId: string): ScanResult | null {
  const resource = (template.Resources ?? {})[logicalId]!;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  const adapter: Apigw005Adapter = factory.bind(context);
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 (CloudFormation) - REQ-01: REST API with no endpoint-type configuration', () => {
  // Primary behavior owned by this requirement: absent EndpointConfiguration
  // defaults to a public (edge-optimized) endpoint and must be flagged. Like an
  // explicitly public endpoint type (REQ-15), this only applies when the
  // template defines VPC-attached callers.
  it('flags a REST API declared with no endpoint-type configuration at all', () => {
    const template: Template = {
      Resources: {
        PublicByDefaultApi: {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'orders-api',
            Description: 'No EndpointConfiguration specified',
          },
        },
        CallerInstance: {
          Type: 'AWS::EC2::Instance',
          Properties: {
            ImageId: 'ami-12345678',
            InstanceType: 't3.micro',
            SubnetId: 'subnet-0123456789abcdef0',
          },
        },
      },
    } as unknown as Template;

    const result = scan(template, 'PublicByDefaultApi');

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('APIGW-005');
    expect(result!.resourceName).toBe('PublicByDefaultApi');
    expect(result!.resourceType).toBe('AWS::ApiGateway::RestApi');
  });

  // Opposite outcome: the nearest input that flips the verdict - the same API
  // with a PRIVATE endpoint type reachable through a properly configured
  // execute-api VPC endpoint.
  it('does not flag an otherwise identical REST API configured as a PRIVATE endpoint behind a properly configured VPC endpoint', () => {
    const template: Template = {
      Resources: {
        ApiVpcEndpoint: {
          Type: 'AWS::EC2::VPCEndpoint',
          Properties: {
            ServiceName: 'com.amazonaws.us-east-1.execute-api',
            VpcEndpointType: 'Interface',
            VpcId: 'vpc-0123456789abcdef0',
            SubnetIds: ['subnet-aaa111', 'subnet-bbb222'],
            SecurityGroupIds: ['sg-0123456789abcdef0'],
            PrivateDnsEnabled: true,
          },
        },
        PublicByDefaultApi: {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'orders-api',
            Description: 'No EndpointConfiguration specified',
            EndpointConfiguration: {
              Types: ['PRIVATE'],
              VpcEndpointIds: [{ Ref: 'ApiVpcEndpoint' }],
            },
          },
        },
      },
    } as unknown as Template;

    // Ref to a logical id resolves to the logical id string after preprocessing.
    (template.Resources!['PublicByDefaultApi'] as any).Properties.EndpointConfiguration.VpcEndpointIds = [
      'ApiVpcEndpoint',
    ];

    const result = scan(template, 'PublicByDefaultApi');

    expect(result).toBeNull();
  });

  // An absent endpoint type deploys as a public one, so REQ-15's scope
  // condition applies: with no VPC-attached callers the API is out of scope.
  it('does not flag a REST API with no endpoint-type configuration when the template has no VPC-attached callers', () => {
    const template: Template = {
      Resources: {
        PublicByDefaultApi: {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'orders-api',
            Description: 'No EndpointConfiguration specified',
          },
        },
      },
    } as unknown as Template;

    const result = scan(template, 'PublicByDefaultApi');

    expect(result).toBeNull();
  });
});
