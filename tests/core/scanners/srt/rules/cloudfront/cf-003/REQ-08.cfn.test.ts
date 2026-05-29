import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-003 REQ-08 (CloudFormation): unresolvable inline logging destination bucket', () => {
  it('does not flag the distribution when the inline logging Bucket value depends on an unresolved Fn::If condition', () => {
    // Note: Fn::If is NOT resolved by parseCfnTemplate preprocessing; it remains
    // as an object. This represents a destination bucket whose value cannot be
    // determined statically at analysis time.
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'origin1',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'origin1',
                  DomainName: 'example.com',
                },
              ],
              Logging: {
                Bucket: {
                  'Fn::If': [
                    'UseExternalLoggingBucket',
                    'external-bucket.s3.amazonaws.com',
                    'internal-bucket.s3.amazonaws.com',
                  ],
                },
                IncludeCookies: false,
                Prefix: 'cf-logs/',
              },
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new Cf003CfnAdapterFactory();
    const logicalId = 'MyDistribution';
    const resource = template.Resources![logicalId];

    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const adapter = factory.bind(context);
    const result = cf003Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
