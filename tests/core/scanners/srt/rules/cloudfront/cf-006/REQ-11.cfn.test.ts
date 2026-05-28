import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-11 (CloudFormation): A CloudFront distribution has an OAC-eligible non-S3 origin
 * (Lambda function URL, MediaStore, or MediaPackage v2) where the OriginAccessControlId
 * value is an unresolvable expression (e.g., Fn::If, Fn::ImportValue).
 *
 * Per resolved decision, unresolvable values cannot be asserted as non-compliant on any
 * origin type. Expected behavior: PASS (no finding).
 */
describe('CF-006 REQ-11 (CFN): non-S3 OAC-eligible origin with unresolvable OriginAccessControlId', () => {
  const factory = new Cf006CfnAdapterFactory();

  function runRule(template: Template, logicalId: string) {
    const resource = (template.Resources as any)[logicalId];
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };
    const adapter = factory.bind(context);
    return cf006Control.run(adapter as any, context);
  }

  it('passes when a Lambda Function URL origin has OriginAccessControlId from Fn::ImportValue (unresolved)', () => {
    const template: Template = {
      Resources: {
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'lambda-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'lambda-origin',
                  DomainName: 'abc123.lambda-url.us-east-1.on.aws',
                  // Fn::ImportValue is NOT resolved by preprocessing — remains an object
                  OriginAccessControlId: { 'Fn::ImportValue': 'shared-oac-id' },
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                  },
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const result = runRule(template, 'Distribution');
    expect(result).toBeNull();
  });

  it('passes when a MediaStore origin has OriginAccessControlId from Fn::If (unresolved)', () => {
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
                  DomainName: 'mycontainer.data.mediastore.us-east-1.amazonaws.com',
                  // Fn::If is NOT resolved by preprocessing — remains an object
                  OriginAccessControlId: {
                    'Fn::If': ['UseOac', 'someOacId', { Ref: 'AWS::NoValue' }],
                  },
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                  },
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const result = runRule(template, 'Distribution');
    expect(result).toBeNull();
  });

  it('passes when a MediaPackage v2 origin has OriginAccessControlId from Fn::ImportValue (unresolved)', () => {
    const template: Template = {
      Resources: {
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'mp2-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'mp2-origin',
                  DomainName: 'abcd1234.egress.mediapackagev2.us-east-1.amazonaws.com',
                  OriginAccessControlId: { 'Fn::ImportValue': 'cross-stack-oac' },
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                  },
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const result = runRule(template, 'Distribution');
    expect(result).toBeNull();
  });
});
