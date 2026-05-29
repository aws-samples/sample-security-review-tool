import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-003 / REQ-03 (CloudFormation): inline access logging with destination bucket only (no prefix) should pass', () => {
  it('returns no scan result when Logging has Bucket set and Prefix omitted', () => {
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
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                  },
                },
              ],
              Logging: {
                Bucket: 'my-access-logs-bucket.s3.amazonaws.com',
                // Prefix intentionally omitted - it is optional per CloudFront Logging spec
              },
            },
          },
        },
      },
    };

    const factory = new Cf003CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyDistribution,
      logicalId: 'MyDistribution',
    };

    const adapter = factory.bind(context);
    const result = cf003Control.run(adapter, context);

    expect(adapter.hasAccessLogging).toBe(true);
    expect(result).toBeNull();
  });
});
