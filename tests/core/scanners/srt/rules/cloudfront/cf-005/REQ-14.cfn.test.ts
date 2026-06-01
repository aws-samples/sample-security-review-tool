import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 CloudFormation - REQ-14: multiple custom origins all HTTPS-only with secure TLS', () => {
  it('passes when every custom origin uses https-only and only TLSv1.2/TLSv1.3 are allowed', () => {
    const resource = {
      Type: 'AWS::CloudFront::Distribution',
      Properties: {
        DistributionConfig: {
          Enabled: true,
          DefaultCacheBehavior: {
            TargetOriginId: 'customOriginA',
            ViewerProtocolPolicy: 'redirect-to-https',
          },
          Origins: [
            {
              Id: 'customOriginA',
              DomainName: 'a.example.com',
              CustomOriginConfig: {
                OriginProtocolPolicy: 'https-only',
                OriginSSLProtocols: ['TLSv1.2'],
              },
            },
            {
              Id: 'customOriginB',
              DomainName: 'b.example.com',
              CustomOriginConfig: {
                OriginProtocolPolicy: 'https-only',
                OriginSSLProtocols: ['TLSv1.2', 'TLSv1.3'],
              },
            },
            {
              Id: 'customOriginC',
              DomainName: 'c.example.com',
              CustomOriginConfig: {
                OriginProtocolPolicy: 'https-only',
                OriginSSLProtocols: ['TLSv1.3'],
              },
            },
          ],
        },
      },
    } as never;

    const context: CfnContext = {
      stackName: 'test-stack',
      template: { Resources: { MyDistribution: resource } } as never,
      resource,
      logicalId: 'MyDistribution',
    };

    const adapter = new Cf005CfnAdapterFactory().bind(context);
    const result = cf005Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
