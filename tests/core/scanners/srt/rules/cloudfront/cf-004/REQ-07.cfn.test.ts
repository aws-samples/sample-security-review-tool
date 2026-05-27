import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-004 / REQ-07 (CloudFormation): disabled distribution with non-compliant cache behavior', () => {
  it('flags a disabled distribution whose default cache behavior allows HTTP', () => {
    const template: Template = {
      Resources: {
        DisabledDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: false,
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

    const resource = template.Resources!['DisabledDistribution'];
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'DisabledDistribution',
    };

    const factory = new Cf004CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-004');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe('DisabledDistribution');
    expect(result?.status).toBe('Open');
  });
});
