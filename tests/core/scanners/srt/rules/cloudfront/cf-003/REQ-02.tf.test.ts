import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-003 REQ-02 Terraform - inline access logging with non-empty destination bucket', () => {
  it('passes when aws_cloudfront_distribution has logging_config with a bucket', () => {
    const distribution: TerraformResource = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        enabled: true,
        logging_config: [
          {
            bucket: 'my-cloudfront-logs.s3.amazonaws.com',
            include_cookies: false,
            prefix: '',
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [distribution];

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const factory = new Cf003TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf003Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
