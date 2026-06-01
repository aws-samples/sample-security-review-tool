import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-08 CloudFormation: multiple origins, S3 origins have OAC, non-S3 origins are out of scope', () => {
  it('passes when every S3 origin has a resolved OAC and other origins are custom HTTP origins', () => {
    const template: Template = {
      Resources: {
        AssetsBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        MediaBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        AssetsOac: {
          Type: 'AWS::CloudFront::OriginAccessControl',
          Properties: {
            OriginAccessControlConfig: {
              Name: 'assets-oac',
              OriginAccessControlOriginType: 's3',
              SigningBehavior: 'always',
              SigningProtocol: 'sigv4',
            },
          },
        },
        MediaOac: {
          Type: 'AWS::CloudFront::OriginAccessControl',
          Properties: {
            OriginAccessControlConfig: {
              Name: 'media-oac',
              OriginAccessControlOriginType: 's3',
              SigningBehavior: 'always',
              SigningProtocol: 'sigv4',
            },
          },
        },
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'assets-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'assets-origin',
                  // Resource reference -> resolves to logical ID "AssetsBucket"
                  DomainName: 'AssetsBucket',
                  S3OriginConfig: {},
                  // Resource reference -> resolves to logical ID "AssetsOac"
                  OriginAccessControlId: 'AssetsOac',
                },
                {
                  Id: 'media-origin',
                  // Literal S3 regional domain
                  DomainName: 'media-bucket.s3.us-east-1.amazonaws.com',
                  S3OriginConfig: {},
                  OriginAccessControlId: 'MediaOac',
                },
                {
                  Id: 'api-origin',
                  // Custom HTTP origin — not S3, not OAC-eligible
                  DomainName: 'api.example.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                  },
                },
                {
                  Id: 'legacy-origin',
                  // Another custom HTTP origin
                  DomainName: 'legacy.example.com',
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
    expect(adapter.findS3OriginsWithoutAccessControl()).toEqual([]);
  });
});
