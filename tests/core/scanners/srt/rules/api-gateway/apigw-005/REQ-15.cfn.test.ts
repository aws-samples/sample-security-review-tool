import { describe, expect, it } from 'vitest';
import { apigw005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.cfn.js';
import type { Apigw005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-005/apigw-005.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const REST_API_LOGICAL_ID = 'PublicRestApi';

const publicRestApi = {
  Type: 'AWS::ApiGateway::RestApi',
  Properties: {
    Name: 'public-api',
    EndpointConfiguration: {
      Types: ['REGIONAL'],
    },
  },
};

/** An EC2 instance placed in a subnet — a VPC-attached caller of the API. */
const vpcAttachedInstance = {
  Type: 'AWS::EC2::Instance',
  Properties: {
    ImageId: 'ami-12345678',
    InstanceType: 't3.micro',
    SubnetId: 'subnet-0123456789abcdef0',
  },
};

function buildTemplate(extraResources: Record<string, unknown> = {}): Template {
  return {
    Resources: {
      [REST_API_LOGICAL_ID]: publicRestApi,
      ...extraResources,
    },
  } as unknown as Template;
}

function runControl(template: Template): ScanResult | null {
  const resource = (template.Resources ?? {})[REST_API_LOGICAL_ID] as Resource;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: REST_API_LOGICAL_ID,
  };
  const adapter = new Apigw005CfnAdapterFactory().bind(context) as Apigw005Adapter;
  return apigw005Control.run(adapter, context);
}

describe('APIGW-005 (CloudFormation) - public REST API with no VPC-attached callers', () => {
  // Primary behavior owned by this requirement: the rule only governs APIs whose
  // callers live inside a VPC, so a public endpoint with no VPC-attached compute passes.
  it('passes a REGIONAL (public) REST API when the template has no VPC-attached compute resources', () => {
    const result = runControl(buildTemplate());

    expect(result).toBeNull();
  });

  // Opposite outcome: identical public REST API, but now a VPC-attached caller exists.
  it('flags the same public REST API when the template contains a VPC-attached EC2 instance', () => {
    const result = runControl(buildTemplate({ VpcInstance: vpcAttachedInstance }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-005');
    expect(result?.resourceName).toBe(REST_API_LOGICAL_ID);
  });
});
