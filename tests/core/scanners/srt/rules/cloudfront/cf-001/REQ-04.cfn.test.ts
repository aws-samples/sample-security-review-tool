import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-04 (CloudFormation):
 * Scenario: CloudFront distribution explicitly sets MinimumProtocolVersion to a value
 * that permits TLS versions below 1.2 (e.g., SSLv3, TLSv1, TLSv1_2016, TLSv1.1_2016).
 * Expected Behavior: flag
 */

function buildContext(template: Template, logicalId: string): CfnContext {
  const resource = template.Resources![logicalId];
  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
}

function runControl(template: Template, logicalId: string) {
  const factory = new Cf001CfnAdapterFactory();
  const context = buildContext(template, logicalId);
  const adapter = factory.bind(context);
  return cf001Control.run(adapter, context);
}

describe('CF-001 REQ-04 CloudFormation: MinimumProtocolVersion below TLS 1.2 should be flagged', () => {
  const insecureProtocolVersions = ['SSLv3', 'TLSv1', 'TLSv1_2016', 'TLSv1.1_2016'];

  for (const version of insecureProtocolVersions) {
    it(`flags a CloudFront distribution that sets MinimumProtocolVersion to ${version}`, () => {
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
                  MinimumProtocolVersion: version,
                },
              },
            },
          },
        },
      };

      const result = runControl(template, 'MyDistribution');

      expect(result).not.toBeNull();
      expect(result?.check_id).toBe('CF-001');
      expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
      expect(result?.resourceName).toBe('MyDistribution');
      expect(result?.status).toBe('Open');
    });
  }
});
