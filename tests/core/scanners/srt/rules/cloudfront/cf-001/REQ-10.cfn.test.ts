import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-001 (CloudFormation) - REQ-10: custom certificate without minimum protocol version', () => {
  it('flags a CloudFront distribution that uses a custom ACM certificate but does not specify a MinimumProtocolVersion', () => {
    const logicalId = 'MyDistribution';
    const template: Template = {
      Resources: {
        [logicalId]: {
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
              },
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources![logicalId],
      logicalId,
    };

    const factory = new Cf001CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-001');
    expect(result!.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result!.resourceName).toBe(logicalId);
    expect(result!.status).toBe('Open');
    expect(result!.issue).toContain('minimum TLS protocol version');
  });

  it('flags a CloudFront distribution that uses a custom IAM certificate but does not specify a MinimumProtocolVersion', () => {
    const logicalId = 'IamCertDistribution';
    const template: Template = {
      Resources: {
        [logicalId]: {
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
                IamCertificateId: 'ASCAEXAMPLE',
                SslSupportMethod: 'sni-only',
              },
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources![logicalId],
      logicalId,
    };

    const adapter = new Cf001CfnAdapterFactory().bind(context);
    const result = cf001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-001');
    expect(result!.resourceName).toBe(logicalId);
    expect(result!.issue).toContain('minimum TLS protocol version');
  });
});
