import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 CloudFormation - REQ-01: distribution with no origins defined', () => {
  it('passes when a CloudFront distribution has no origins defined at all', () => {
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'placeholder',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              // No Origins property defined at all - no custom origins to evaluate
            },
          },
        },
      },
    };

    const resource = template.Resources!['MyDistribution'];
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

    // No custom origins -> no insecure origin connection to flag -> pass (null)
    expect(result).toBeNull();
  });
});
