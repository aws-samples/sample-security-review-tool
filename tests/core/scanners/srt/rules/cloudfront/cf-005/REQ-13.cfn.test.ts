import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 CloudFormation - REQ-13: unresolvable SSL/TLS protocols list contents', () => {
  it('passes when the custom origin uses HTTPS but the OriginSSLProtocols list contents are unresolvable (Fn::If element)', () => {
    const template = {
      Conditions: {
        UseModernTls: { 'Fn::Equals': [{ Ref: 'AWS::Region' }, 'us-east-1'] },
      },
      Resources: {
        Distro: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              Origins: [
                {
                  Id: 'custom-origin',
                  DomainName: 'origin.example.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                    // The protocol list itself is present, but its contents
                    // depend on a CloudFormation Condition and cannot be
                    // resolved at analysis time. After preprocessing, the
                    // Fn::If remains an opaque object inside the array.
                    OriginSSLProtocols: [
                      {
                        'Fn::If': ['UseModernTls', 'TLSv1.2', 'TLSv1'],
                      },
                    ],
                  },
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const resource = template.Resources!['Distro']!;
    const ctx: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'Distro',
    };

    const factory = new Cf005CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);
    const adapter = factory.bind(ctx);
    const result = cf005Control.run(adapter, ctx);

    expect(result).toBeNull();
  });
});
