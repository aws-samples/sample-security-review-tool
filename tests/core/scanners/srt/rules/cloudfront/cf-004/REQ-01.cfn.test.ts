import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-004 CloudFormation - REQ-01: default cache behavior with no viewer protocol policy', () => {
  it('flags a distribution whose default cache behavior is missing ViewerProtocolPolicy', () => {
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'origin1',
                // ViewerProtocolPolicy intentionally omitted
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

    const logicalId = 'MyDistribution';
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
    expect(result?.resourceName).toBe('MyDistribution');
    expect(result?.status).toBe('Open');
  });
});
