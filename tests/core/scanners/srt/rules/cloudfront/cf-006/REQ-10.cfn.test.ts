import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (CF-006): A CloudFront distribution has only non-S3 origins that are nevertheless
 * OAC-eligible (Lambda function URL origins, MediaStore origins, MediaPackage v2 origins) and
 * none of them has an origin access control attached. Expected behavior: flag.
 */

function buildCfnContext(distributionLogicalId: string, origins: any[], extraResources: Record<string, any> = {}): CfnContext {
  const template: any = {
    Resources: {
      [distributionLogicalId]: {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: origins,
          },
        },
      },
      ...extraResources,
    },
  };

  return {
    stackName: 'test-stack',
    template,
    resource: template.Resources[distributionLogicalId],
    logicalId: distributionLogicalId,
  };
}

function runRule(context: CfnContext) {
  const factory = new Cf006CfnAdapterFactory();
  const adapter = factory.bind(context);
  return cf006Control.run(adapter, context);
}

describe('CF-006 REQ-10 [CFN] - Non-S3 OAC-eligible origins without OAC', () => {
  it('flags a distribution whose only origin is a Lambda function URL without OAC', () => {
    const ctx = buildCfnContext('LambdaUrlDistribution', [
      {
        Id: 'lambda-fn-url-origin',
        DomainName: 'abcdefghij.lambda-url.us-east-1.on.aws',
        CustomOriginConfig: {
          OriginProtocolPolicy: 'https-only',
        },
      },
    ]);

    const result = runRule(ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceName).toBe('LambdaUrlDistribution');
  });

  it('flags a distribution whose only origin is a MediaStore origin without OAC', () => {
    const ctx = buildCfnContext('MediaStoreDistribution', [
      {
        Id: 'mediastore-origin',
        DomainName: 'examplecontainer.data.mediastore.us-east-1.amazonaws.com',
        CustomOriginConfig: {
          OriginProtocolPolicy: 'https-only',
        },
      },
    ]);

    const result = runRule(ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceName).toBe('MediaStoreDistribution');
  });

  it('flags a distribution whose only origin is a MediaPackage v2 origin without OAC', () => {
    const ctx = buildCfnContext('MediaPackageV2Distribution', [
      {
        Id: 'mediapackagev2-origin',
        DomainName: 'abc123.egress.mediapackagev2.us-east-1.amazonaws.com',
        CustomOriginConfig: {
          OriginProtocolPolicy: 'https-only',
        },
      },
    ]);

    const result = runRule(ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceName).toBe('MediaPackageV2Distribution');
  });

  it('flags a distribution that has multiple non-S3 OAC-eligible origins all missing OAC', () => {
    const ctx = buildCfnContext('MixedOacEligibleDistribution', [
      {
        Id: 'lambda-url',
        DomainName: 'aaaaaaaaaa.lambda-url.us-east-1.on.aws',
        CustomOriginConfig: { OriginProtocolPolicy: 'https-only' },
      },
      {
        Id: 'mediastore',
        DomainName: 'examplecontainer.data.mediastore.us-east-1.amazonaws.com',
        CustomOriginConfig: { OriginProtocolPolicy: 'https-only' },
      },
      {
        Id: 'mediapackagev2',
        DomainName: 'abc123.egress.mediapackagev2.us-east-1.amazonaws.com',
        CustomOriginConfig: { OriginProtocolPolicy: 'https-only' },
      },
    ]);

    const result = runRule(ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
  });
});
