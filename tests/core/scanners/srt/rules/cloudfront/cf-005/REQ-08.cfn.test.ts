import { describe, expect, it } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 REQ-08 (CloudFormation): custom origin with https-only but no OriginSSLProtocols', () => {
  it('flags a custom origin that omits OriginSSLProtocols even when OriginProtocolPolicy is https-only', () => {
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'custom-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'custom-origin',
                  DomainName: 'origin.example.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                    // OriginSSLProtocols is intentionally omitted
                  },
                },
              ],
            },
          },
        },
      },
    };

    const resource = template.Resources!['MyDistribution']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyDistribution',
    };

    const factory = new Cf005CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);
    const adapter = factory.bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.resourceName).toBe('MyDistribution');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
  });
});
