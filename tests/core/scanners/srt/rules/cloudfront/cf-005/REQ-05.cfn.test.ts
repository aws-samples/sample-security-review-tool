import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 CloudFormation - REQ-05: HTTPS-only custom origin with secure TLS protocols', () => {
  it('passes when a custom origin uses https-only with a secure-only TLS protocol list (TLS 1.2+)', () => {
    const template: Template = {
      Resources: {
        SecureDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'customOrigin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'customOrigin',
                  DomainName: 'origin.example.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                    OriginSSLProtocols: ['TLSv1.2'],
                  },
                },
              ],
            },
          },
        },
      },
    };

    const resource = template.Resources!['SecureDistribution']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'SecureDistribution',
    };

    const factory = new Cf005CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when a custom origin uses https-only with multiple secure TLS versions (TLS 1.2 and 1.3)', () => {
    const template: Template = {
      Resources: {
        SecureDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'customOrigin',
                ViewerProtocolPolicy: 'https-only',
              },
              Origins: [
                {
                  Id: 'customOrigin',
                  DomainName: 'api.example.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                    OriginSSLProtocols: ['TLSv1.2', 'TLSv1.3'],
                  },
                },
              ],
            },
          },
        },
      },
    };

    const resource = template.Resources!['SecureDistribution']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'SecureDistribution',
    };

    const adapter = new Cf005CfnAdapterFactory().bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
