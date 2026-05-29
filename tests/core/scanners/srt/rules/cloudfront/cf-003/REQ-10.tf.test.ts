import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-003 REQ-10 Terraform: inline access logging with bucket as a reference to another resource', () => {
  it('passes when logging_config.bucket value is a resolved reference to another resource (e.g., a bucket regional domain name)', () => {
    // In a Terraform plan, references like aws_s3_bucket.logs.bucket_regional_domain_name
    // are resolved to a concrete string in the values object. The adapter only checks that
    // the bucket value is a non-empty string (or any non-null object), so a resolved reference
    // counts as a valid destination.
    const logBucket: TerraformResource = {
      address: 'aws_s3_bucket.logs',
      type: 'aws_s3_bucket',
      name: 'logs',
      values: {
        bucket: 'my-cf-log-bucket',
        bucket_regional_domain_name: 'my-cf-log-bucket.s3.us-east-1.amazonaws.com',
      },
    } as unknown as TerraformResource;

    const distribution: TerraformResource = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      values: {
        enabled: true,
        logging_config: [
          {
            // This is the value Terraform produces after resolving
            // aws_s3_bucket.logs.bucket_regional_domain_name
            bucket: 'my-cf-log-bucket.s3.us-east-1.amazonaws.com',
            include_cookies: false,
            prefix: 'cf-logs/',
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [logBucket, distribution];

    const factory = new Cf003TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    expect(factory.appliesTo(distribution.type)).toBe(true);
    const adapter = factory.bind(context);
    const result = cf003Control.run(adapter, context);

    expect(adapter.hasAccessLogging).toBe(true);
    expect(result).toBeNull();
  });
});
