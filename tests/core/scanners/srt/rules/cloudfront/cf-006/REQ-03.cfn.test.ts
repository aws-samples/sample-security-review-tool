import { describe, expect, it } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-03 (CloudFormation): S3 origin with legacy OAI but no OAC', () => {
  it('passes when an S3 bucket origin uses legacy OriginAccessIdentity even though OAC is not configured', () => {
    const template: Template = {
      Resources: {
        SiteBucket: {
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
                  DomainName: 'SiteBucket',
                  S3OriginConfig: {
                    OriginAccessIdentity: 'origin-access-identity/cloudfront/E1ABCDEFGHIJK',
                  },
                },
              ],
            },
          },
        },
      },
    };

    const distribution = template.Resources!['Distribution']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: distribution,
      logicalId: 'Distribution',
    };

    const factory = new Cf006CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
