import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-11 (CloudFormation): A CloudFront distribution has an OAC-eligible non-S3 origin
 * (Lambda function URL, MediaStore, or MediaPackage v2) where the OriginAccessControlId
 * value is provided via an unresolvable expression (e.g. Fn::If, Fn::ImportValue).
 *
 * Expected: pass (no finding) — per resolved decision, unresolvable values cannot be
 * asserted as non-compliant on any origin type.
 */

function runControl(template: Template, logicalId: string) {
  const factory = new Cf006CfnAdapterFactory();
  const resource = template.Resources![logicalId];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  const adapter = factory.bind(context);
  return cf006Control.run(adapter, context);
}

describe('CF-006 REQ-11 (CFN): non-S3 OAC-eligible origin with unresolvable OriginAccessControlId', () => {
  it('passes when a Lambda function URL origin has OriginAccessControlId provided via Fn::If', () => {
    const template: Template = {
      Resources: {
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [
                {
                  Id: 'lambda-origin',
                  DomainName: 'abcdef1234.lambda-url.us-east-1.on.aws',
                  OriginAccessControlId: {
                    'Fn::If': ['UseOac', 'SomeOacResource', { Ref: 'AWS::NoValue' }],
                  },
                },
              ],
            },
          },
        },
      },
    };

    const result = runControl(template, 'Distribution');
    expect(result).toBeNull();
  });

  it('passes when a MediaStore origin has OriginAccessControlId provided via Fn::ImportValue', () => {
    const template: Template = {
      Resources: {
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [
                {
                  Id: 'mediastore-origin',
                  DomainName: 'mycontainer.data.mediastore.us-east-1.amazonaws.com',
                  OriginAccessControlId: {
                    'Fn::ImportValue': 'shared-oac-id',
                  },
                },
              ],
            },
          },
        },
      },
    };

    const result = runControl(template, 'Distribution');
    expect(result).toBeNull();
  });

  it('passes when a MediaPackage v2 origin has OriginAccessControlId provided via Fn::If', () => {
    const template: Template = {
      Resources: {
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [
                {
                  Id: 'mediapackagev2-origin',
                  DomainName: 'channel.egress.mediapackagev2.us-east-1.amazonaws.com',
                  OriginAccessControlId: {
                    'Fn::If': ['UseOac', 'SomeOacResource', { Ref: 'AWS::NoValue' }],
                  },
                },
              ],
            },
          },
        },
      },
    };

    const result = runControl(template, 'Distribution');
    expect(result).toBeNull();
  });
});
