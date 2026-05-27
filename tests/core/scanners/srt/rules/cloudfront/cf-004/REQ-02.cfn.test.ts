import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-004 / REQ-02 / CloudFormation: Default cache behavior allows both HTTP and HTTPS (allow-all)', () => {
  it('flags a distribution whose default cache behavior viewer protocol policy is allow-all', () => {
    const template: Template = {
      Resources: {
        InsecureDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'origin1',
                ViewerProtocolPolicy: 'allow-all',
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
            },
          },
        },
      },
    };

    const logicalId = 'InsecureDistribution';
    const resource = template.Resources![logicalId];

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new Cf004CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-004');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe(logicalId);
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });
});
