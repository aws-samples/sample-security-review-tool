import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 REQ-02 (CloudFormation): distribution with only native S3 origins (no custom origins)', () => {
  it('passes when all origins are native S3 origins (S3OriginConfig) and there are no custom origins', () => {
    const template: Template = {
      Resources: {
        OriginBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 's3-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 's3-origin',
                  DomainName: 'OriginBucket',
                  S3OriginConfig: {
                    OriginAccessIdentity: '',
                  },
                },
              ],
            },
          },
        },
      },
    };

    const factory = new Cf005CfnAdapterFactory();
    const logicalId = 'Distribution';
    const resource = template.Resources![logicalId];

    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const adapter = factory.bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when there are multiple native S3 origins and no custom origins', () => {
    const template: Template = {
      Resources: {
        BucketA: { Type: 'AWS::S3::Bucket', Properties: {} },
        BucketB: { Type: 'AWS::S3::Bucket', Properties: {} },
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 's3-a',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 's3-a',
                  DomainName: 'BucketA',
                  S3OriginConfig: { OriginAccessIdentity: '' },
                },
                {
                  Id: 's3-b',
                  DomainName: 'BucketB',
                  S3OriginConfig: {
                    OriginAccessIdentity: 'origin-access-identity/cloudfront/E127EXAMPLE51Z',
                  },
                },
              ],
            },
          },
        },
      },
    };

    const factory = new Cf005CfnAdapterFactory();
    const logicalId = 'Distribution';
    const resource = template.Resources![logicalId];

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const adapter = factory.bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
