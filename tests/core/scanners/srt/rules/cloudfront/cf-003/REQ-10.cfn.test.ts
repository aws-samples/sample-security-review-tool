import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-003 REQ-10 CloudFormation: inline access logging with bucket as a logical resource reference', () => {
  it('passes when DistributionConfig.Logging.Bucket is a Ref to another resource (resolves to its logical ID string)', () => {
    // After parseCfnTemplate preprocessing, !Ref LogBucket resolves to the string "LogBucket".
    const template: Template = {
      Resources: {
        LogBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              Logging: {
                // Simulating preprocessed value of !Ref LogBucket
                Bucket: 'LogBucket',
                IncludeCookies: false,
                Prefix: 'cf-logs/',
              },
              DefaultCacheBehavior: {
                TargetOriginId: 'origin1',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new Cf003CfnAdapterFactory();
    const distribution = template.Resources!.MyDistribution;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: distribution,
      logicalId: 'MyDistribution',
    };

    expect(factory.appliesTo(distribution.Type)).toBe(true);
    const adapter = factory.bind(context);
    const result = cf003Control.run(adapter, context);

    expect(adapter.hasAccessLogging).toBe(true);
    expect(result).toBeNull();
  });
});
