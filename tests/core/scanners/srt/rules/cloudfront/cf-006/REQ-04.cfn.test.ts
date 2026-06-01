import { describe, it, expect } from 'vitest';
import { Cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-04 (CFN): A CloudFront distribution has an S3 bucket origin whose origin access
 * control identifier is an empty string or otherwise unset.
 * Expected: flag (S3_ORIGIN_WITHOUT_ACCESS_CONTROL).
 */
describe('CF-006 REQ-04 (CloudFormation): S3 origin with empty/unset OriginAccessControlId is flagged', () => {
  const control = new Cf006Control();
  const factory = new Cf006CfnAdapterFactory();

  function runControl(template: Template, logicalId: string) {
    const resource = template.Resources![logicalId];
    const ctx: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };
    const adapter = factory.bind(ctx);
    return control.run(adapter, ctx);
  }

  it('flags an S3 origin (S3OriginConfig) when OriginAccessControlId is an empty string and no legacy OAI', () => {
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
              Origins: [
                {
                  Id: 's3-origin',
                  DomainName: 'SiteBucket',
                  OriginAccessControlId: '',
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

    const result = runControl(template, 'Distribution');

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-006');
    expect(result!.resourceName).toBe('Distribution');
    expect(result!.issue).toMatch(/S3 bucket origin/i);
  });

  it('flags an S3 origin when OriginAccessControlId is omitted entirely and no legacy OAI', () => {
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
              Origins: [
                {
                  Id: 's3-origin',
                  DomainName: 'SiteBucket',
                  S3OriginConfig: {},
                },
              ],
            },
          },
        },
      },
    };

    const result = runControl(template, 'Distribution');

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-006');
  });

  it('flags an S3 origin identified by literal S3 domain name when OriginAccessControlId is whitespace-only', () => {
    const template: Template = {
      Resources: {
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [
                {
                  Id: 's3-literal-origin',
                  DomainName: 'my-bucket.s3.us-east-1.amazonaws.com',
                  OriginAccessControlId: '   ',
                },
              ],
            },
          },
        },
      },
    };

    const result = runControl(template, 'Distribution');

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-006');
  });
});
