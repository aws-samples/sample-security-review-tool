import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-001 CloudFormation - REQ-02: ViewerCertificate present but MinimumProtocolVersion missing', () => {
  it('flags a CloudFront distribution that declares a ViewerCertificate without a MinimumProtocolVersion', () => {
    const template: Template = {
      Resources: {
        Distribution: {
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
                // Intentionally missing MinimumProtocolVersion
                AcmCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
                SslSupportMethod: 'sni-only',
              },
            },
          },
        },
      },
    };

    const logicalId = 'Distribution';
    const resource = template.Resources![logicalId];
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new Cf001CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-001');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe('Distribution');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });
});
