import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 CloudFormation - REQ-12: unresolvable custom origin protocol policy', () => {
  it('passes when the custom origin protocol policy is an unresolved Fn::If object', () => {
    // Fn::If is NOT resolved by parseCfnTemplate — it remains as an opaque object.
    // The adapter only treats string values as protocolPolicy, so an unresolved
    // intrinsic becomes `undefined` (unknown). We provide a secure SSL protocol list
    // so the only ambiguity under test is the protocol policy itself.
    const resource = {
      Type: 'AWS::CloudFront::Distribution',
      Properties: {
        DistributionConfig: {
          Origins: [
            {
              Id: 'custom-origin-1',
              DomainName: 'example.com',
              CustomOriginConfig: {
                OriginProtocolPolicy: {
                  'Fn::If': ['UseHttpsOnly', 'https-only', 'http-only'],
                },
                OriginSSLProtocols: ['TLSv1.2'],
              },
            },
          ],
        },
      },
    } as unknown as CfnContext['resource'];

    const context: CfnContext = {
      stackName: 'test-stack',
      template: { Resources: { Dist: resource } } as unknown as CfnContext['template'],
      resource,
      logicalId: 'Dist',
    };

    const adapter = new Cf005CfnAdapterFactory().bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when the custom origin protocol policy is an unresolved Fn::ImportValue object', () => {
    const resource = {
      Type: 'AWS::CloudFront::Distribution',
      Properties: {
        DistributionConfig: {
          Origins: [
            {
              Id: 'custom-origin-1',
              DomainName: 'example.com',
              CustomOriginConfig: {
                OriginProtocolPolicy: {
                  'Fn::ImportValue': 'SharedProtocolPolicy',
                },
                OriginSSLProtocols: ['TLSv1.2'],
              },
            },
          ],
        },
      },
    } as unknown as CfnContext['resource'];

    const context: CfnContext = {
      stackName: 'test-stack',
      template: { Resources: { Dist: resource } } as unknown as CfnContext['template'],
      resource,
      logicalId: 'Dist',
    };

    const adapter = new Cf005CfnAdapterFactory().bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
