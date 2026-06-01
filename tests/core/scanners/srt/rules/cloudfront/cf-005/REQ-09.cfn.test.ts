import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 REQ-09 (CloudFormation): custom origin HTTPS-only with empty OriginSSLProtocols list', () => {
  it('flags a custom origin that uses https-only but provides an empty OriginSSLProtocols array', () => {
    const template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'custom-origin-1',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'custom-origin-1',
                  DomainName: 'origin.example.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                    OriginSSLProtocols: [],
                  },
                },
              ],
            },
          },
        },
      },
    };

    const resource = template.Resources.MyDistribution;
    const context: CfnContext = {
      stackName: 'test-stack',
      template: template as never,
      resource: resource as never,
      logicalId: 'MyDistribution',
    };

    const factory = new Cf005CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);
    const adapter = factory.bind(context);

    const result = cf005Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.status).toBe('Open');
    expect(result?.resourceName).toBe('MyDistribution');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    // Empty SSL protocols list is treated as "missing" by the rule.
    expect(result?.fix).toContain('Explicitly declare the allowed SSL/TLS protocol list');
  });
});
