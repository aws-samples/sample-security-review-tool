import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-09 CloudFormation: multiple S3 origins where at least one lacks OAC/OAI', () => {
  it('flags when one S3 origin is unprotected even if the others are correctly secured', () => {
    const template: Template = {
      Resources: {
        SecuredBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        UnsecuredBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        LegacyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        DistroOac: {
          Type: 'AWS::CloudFront::OriginAccessControl',
          Properties: {
            OriginAccessControlConfig: {
              Name: 'distro-oac',
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
                TargetOriginId: 'origin-secured-oac',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  // Properly secured via OAC
                  Id: 'origin-secured-oac',
                  DomainName: 'SecuredBucket',
                  OriginAccessControlId: 'DistroOac',
                  S3OriginConfig: {},
                },
                {
                  // Properly secured via legacy OAI
                  Id: 'origin-secured-oai',
                  DomainName: 'LegacyBucket',
                  S3OriginConfig: {
                    OriginAccessIdentity: 'origin-access-identity/cloudfront/E127EXAMPLE51Z',
                  },
                },
                {
                  // UNPROTECTED — no OAC, no OAI
                  Id: 'origin-unsecured',
                  DomainName: 'UnsecuredBucket',
                  S3OriginConfig: {},
                },
              ],
            },
          },
        },
      },
    };

    const factory = new Cf006CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['Distribution']!,
      logicalId: 'Distribution',
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.status).toBe('Open');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe('Distribution');
    expect(result?.issue).toMatch(/S3 bucket origin/i);
  });

  it('exposes the unprotected origin id via the adapter while ignoring the secured ones', () => {
    const template: Template = {
      Resources: {
        SecuredBucket: { Type: 'AWS::S3::Bucket', Properties: {} },
        UnsecuredBucket: { Type: 'AWS::S3::Bucket', Properties: {} },
        DistroOac: {
          Type: 'AWS::CloudFront::OriginAccessControl',
          Properties: {
            OriginAccessControlConfig: {
              Name: 'distro-oac',
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
                TargetOriginId: 'origin-secured',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'origin-secured',
                  DomainName: 'SecuredBucket',
                  OriginAccessControlId: 'DistroOac',
                  S3OriginConfig: {},
                },
                {
                  Id: 'origin-unsecured',
                  DomainName: 'UnsecuredBucket',
                  S3OriginConfig: {},
                },
              ],
            },
          },
        },
      },
    };

    const factory = new Cf006CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['Distribution']!,
      logicalId: 'Distribution',
    };

    const adapter = factory.bind(context);
    const unprotected = adapter.findS3OriginsWithoutAccessControl();

    expect(unprotected).toHaveLength(1);
    expect(unprotected[0]?.originId).toBe('origin-unsecured');
  });
});
