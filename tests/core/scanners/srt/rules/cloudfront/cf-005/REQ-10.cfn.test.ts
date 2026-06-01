import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 CloudFormation - custom origin to S3 website endpoint with HTTP-only', () => {
  it('flags a custom origin that uses http-only protocol policy even when pointing at an S3 static website endpoint', () => {
    const template: Template = {
      Resources: {
        SiteBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            WebsiteConfiguration: {
              IndexDocument: 'index.html',
            },
          },
        },
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 's3-website-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 's3-website-origin',
                  // S3 static website hosting endpoint as a custom origin
                  DomainName: 'sitebucket.s3-website-us-east-1.amazonaws.com',
                  CustomOriginConfig: {
                    // S3 website endpoints only support HTTP from CloudFront,
                    // but the rule must still flag this configuration.
                    OriginProtocolPolicy: 'http-only',
                    HTTPPort: 80,
                  },
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const distribution = template.Resources!['Distribution'];
    const factory = new Cf005CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: distribution,
      logicalId: 'Distribution',
    };

    const adapter = factory.bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-005');
    expect(result!.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result!.resourceName).toBe('Distribution');
    expect(result!.status).toBe('Open');
    expect(result!.issue).toMatch(/HTTP/i);
  });
});
