import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 Terraform - REQ-01: distribution with no origins defined', () => {
  it('passes when an aws_cloudfront_distribution has no origins defined at all', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      address: 'aws_cloudfront_distribution.my_distribution',
      values: {
        enabled: true,
        default_cache_behavior: [
          {
            target_origin_id: 'placeholder',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
        // No `origin` block defined at all - no custom origins to evaluate
      },
    } as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };

    const factory = new Cf005TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf005Control.run(adapter, context);

    // No custom origins -> no insecure origin connection to flag -> pass (null)
    expect(result).toBeNull();
  });
});
