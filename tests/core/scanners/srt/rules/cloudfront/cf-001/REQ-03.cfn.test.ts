import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const TLS_POLICIES = [
  'TLSv1.2_2018',
  'TLSv1.2_2019',
  'TLSv1.2_2021',
  'TLSv1.2_2025',
  'TLSv1.3_2025',
];

describe('CF-001 REQ-03 (CloudFormation): explicit TLS 1.2+ minimum protocol version passes', () => {
  for (const policy of TLS_POLICIES) {
    it(`passes when ViewerCertificate.MinimumProtocolVersion is ${policy}`, () => {
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
                  MinimumProtocolVersion: policy,
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
  }
});
