import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 CloudFormation - REQ-09: multiple origins where one S3 origin lacks OAC/OAI', () => {
  it('flags the distribution when one of multiple S3 origins is unprotected while others are secured', () => {
    const template: any = {
      Resources: {
        SecureOac: {
          Type: 'AWS::CloudFront::OriginAccessControl',
          Properties: {
            OriginAccessControlConfig: {
              Name: 'secure-oac',
              OriginAccessControlOriginType: 's3',
              SigningBehavior: 'always',
              SigningProtocol: 'sigv4',
            },
          },
        },
        SecureBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        UnprotectedBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        LegacyOai: {
          Type: 'AWS::CloudFront::CloudFrontOriginAccessIdentity',
          Properties: {
            CloudFrontOriginAccessIdentityConfig: { Comment: 'legacy' },
          },
        },
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'unprotected-s3',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'secured-by-oac',
                  DomainName: 'secured-by-oac.s3.us-east-1.amazonaws.com',
                  S3OriginConfig: {},
                  OriginAccessControlId: 'SecureOac',
                },
                {
                  Id: 'secured-by-oai',
                  DomainName: 'secured-by-oai.s3.us-east-1.amazonaws.com',
                  S3OriginConfig: {
                    OriginAccessIdentity: 'origin-access-identity/cloudfront/LegacyOai',
                  },
                },
                {
                  Id: 'unprotected-s3',
                  DomainName: 'unprotected-s3.s3.us-east-1.amazonaws.com',
                  S3OriginConfig: {},
                },
              ],
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources.Distribution,
      logicalId: 'Distribution',
    };

    const factory = new Cf006CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.status).toBe('Open');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe('Distribution');
    expect(result?.issue).toContain('S3 bucket origin');
    expect(adapter.unprotectedS3Origins).toHaveLength(1);
    expect(adapter.unprotectedS3Origins[0].originId).toBe('unprotected-s3');
  });
});
