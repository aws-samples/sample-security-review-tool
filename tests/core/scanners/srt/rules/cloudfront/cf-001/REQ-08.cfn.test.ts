import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-001 CloudFormation - REQ-08: Unresolvable minimum protocol version', () => {
  it('passes when MinimumProtocolVersion depends on an unresolvable Fn::If condition', () => {
    // Fn::If is NOT resolved by parseCfnTemplate preprocessing — it remains as
    // an opaque object. The rule cannot determine the actual protocol version
    // at analysis time and should not flag a false positive.
    const template: Template = {
      Conditions: {
        UseStrictTls: { 'Fn::Equals': [{ Ref: 'AWS::Region' }, 'us-east-1'] },
      } as unknown as Template['Conditions'],
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              ViewerCertificate: {
                AcmCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
                SslSupportMethod: 'sni-only',
                MinimumProtocolVersion: {
                  'Fn::If': ['UseStrictTls', 'TLSv1.2_2021', 'TLSv1'],
                },
              },
            },
          },
        },
      },
    } as unknown as Template;

    const resource = template.Resources!.MyDistribution;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyDistribution',
    };

    const factory = new Cf001CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
