import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (CF-006): A CloudFront distribution has only non-S3 origins that are
 * nevertheless OAC-eligible (Lambda function URL, MediaStore, MediaPackage v2)
 * and none of them has an origin access control attached.
 *
 * Expected behavior: FLAG. Per resolved decision, all OAC-eligible origin
 * types must have OAC configured.
 */
describe('CF-006 REQ-10 (CFN): non-S3 OAC-eligible origins without OAC', () => {
  const factory = new Cf006CfnAdapterFactory();

  function buildContext(template: Template, logicalId: string): CfnContext {
    return {
      stackName: 'test-stack',
      template,
      resource: template.Resources![logicalId]!,
      logicalId,
    };
  }

  it('flags a distribution whose only origin is a Lambda function URL with no OAC', () => {
    const template: Template = {
      Resources: {
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'lambda-url-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'lambda-url-origin',
                  DomainName: 'abcd1234.lambda-url.us-east-1.on.aws',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                  },
                },
              ],
            },
          },
        },
      },
    };

    const context = buildContext(template, 'Distribution');
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
  });

  it('flags a distribution whose only origin is a MediaStore origin with no OAC', () => {
    const template: Template = {
      Resources: {
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'mediastore-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'mediastore-origin',
                  DomainName: 'abc123.data.mediastore.us-east-1.amazonaws.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                  },
                },
              ],
            },
          },
        },
      },
    };

    const context = buildContext(template, 'Distribution');
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
  });

  it('flags a distribution whose only origin is a MediaPackage v2 origin with no OAC', () => {
    const template: Template = {
      Resources: {
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'mediapackage-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'mediapackage-origin',
                  DomainName: 'abc123.egress.mediapackagev2.us-east-1.amazonaws.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                  },
                },
              ],
            },
          },
        },
      },
    };

    const context = buildContext(template, 'Distribution');
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
  });
});
