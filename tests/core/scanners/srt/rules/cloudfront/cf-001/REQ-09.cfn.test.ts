import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-001 CloudFormation - REQ-09: custom certificate with TLS 1.2+ minimum protocol version', () => {
  it('passes when distribution uses an ACM certificate and explicitly sets MinimumProtocolVersion to TLSv1.2_2021', () => {
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
              ViewerCertificate: {
                AcmCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
                SslSupportMethod: 'sni-only',
                MinimumProtocolVersion: 'TLSv1.2_2021',
              },
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyDistribution,
      logicalId: 'MyDistribution',
    };

    const factory = new Cf001CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);
    const adapter = factory.bind(context);
    const result = cf001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when distribution uses an IAM certificate and explicitly sets MinimumProtocolVersion to TLSv1.2_2019', () => {
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
              ViewerCertificate: {
                IamCertificateId: 'IAMCERT123',
                SslSupportMethod: 'sni-only',
                MinimumProtocolVersion: 'TLSv1.2_2019',
              },
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyDistribution,
      logicalId: 'MyDistribution',
    };

    const factory = new Cf001CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = cf001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
