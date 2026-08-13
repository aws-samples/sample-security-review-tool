import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (APIGW-005): A REST API that is PRIVATE and wired to a properly configured
 * execute-api VPC endpoint must still be flagged when its resource policy denies or
 * excludes requests arriving through that VPC endpoint (or its VPC), because the
 * intended private invocation path does not actually work.
 */

const VPC_ENDPOINT_LOGICAL_ID = 'ApiVpcEndpoint';

const compliantVpcEndpoint = {
  Type: 'AWS::EC2::VPCEndpoint',
  Properties: {
    // Resolved value of !Sub "com.amazonaws.${AWS::Region}.execute-api"
    ServiceName: 'com.amazonaws.us-east-1.execute-api',
    VpcEndpointType: 'Interface',
    VpcId: 'vpc-0123456789abcdef0',
    SubnetIds: ['subnet-aaa111', 'subnet-bbb222'],
    SecurityGroupIds: ['sg-aaa111'],
    PrivateDnsEnabled: true,
  },
};

function buildTemplate(policy: unknown): Template {
  return {
    Resources: {
      [VPC_ENDPOINT_LOGICAL_ID]: compliantVpcEndpoint,
      PrivateApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'private-api',
          EndpointConfiguration: {
            Types: ['PRIVATE'],
            // !Ref ApiVpcEndpoint resolves to the logical id string
            VpcEndpointIds: [VPC_ENDPOINT_LOGICAL_ID],
          },
          Policy: policy,
        },
      },
    },
  } as unknown as Template;
}

function run(policy: unknown): ScanResult | null {
  const template = buildTemplate(policy);
  const resource = (template.Resources ?? {})['PrivateApi'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'PrivateApi',
  };
  const adapter = new Apigw005CfnAdapterFactory().bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 REQ-12 (CloudFormation): resource policy excludes the private access path', () => {
  it('flags a private API whose policy only allows a different, unrelated VPC endpoint', () => {
    const result = run({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'execute-api:Invoke',
          Resource: 'execute-api:/*',
          Condition: {
            StringEquals: { 'aws:SourceVpce': 'vpce-unrelated0000000' },
          },
        },
      ],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
    expect(result?.resourceName).toBe('PrivateApi');
  });

  it('flags a private API whose policy explicitly denies requests from the associated VPC endpoint', () => {
    const result = run({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'execute-api:Invoke',
          Resource: 'execute-api:/*',
        },
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 'execute-api:Invoke',
          Resource: 'execute-api:/*',
          Condition: {
            StringEquals: { 'aws:SourceVpce': VPC_ENDPOINT_LOGICAL_ID },
          },
        },
      ],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
  });

  // Opposite outcome: identical configuration, but the policy allows the very VPC
  // endpoint that provides the private path — the private route works, so no finding.
  it('does not flag a private API whose policy allows the associated VPC endpoint', () => {
    const result = run({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'execute-api:Invoke',
          Resource: 'execute-api:/*',
          Condition: {
            StringEquals: { 'aws:SourceVpce': VPC_ENDPOINT_LOGICAL_ID },
          },
        },
      ],
    });

    expect(result).toBeNull();
  });
});
