import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-13 (CloudFormation): empty origins collection', () => {
  it('passes when the distribution has an empty Origins array', () => {
    const template: Template = {
      Resources: {
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              Origins: [],
              DefaultCacheBehavior: {
                TargetOriginId: 'none',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['Distribution']!,
      logicalId: 'Distribution',
    };

    const factory = new Cf006CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
