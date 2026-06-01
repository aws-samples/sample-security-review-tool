import { describe, it, expect } from 'vitest';
import { Cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-04 (Terraform): A CloudFront distribution has an S3 bucket origin whose origin access
 * control identifier is an empty string or otherwise unset.
 * Expected: flag (S3_ORIGIN_WITHOUT_ACCESS_CONTROL).
 */
describe('CF-006 REQ-04 (Terraform): S3 origin with empty/unset origin_access_control_id is flagged', () => {
  const control = new Cf006Control();
  const factory = new Cf006TfAdapterFactory();

  function runControl(distribution: TerraformResource, allResources: TerraformResource[]) {
    const ctx: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };
    const adapter = factory.bind(ctx);
    return control.run(adapter, ctx);
  }

  it('flags an S3 origin (reference form) when origin_access_control_id is an empty string and no legacy OAI', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    };

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        origin: [
          {
            origin_id: 's3-origin',
            domain_name: 'aws_s3_bucket.site',
            origin_access_control_id: '',
            s3_origin_config: [{ cloudfront_access_identity_path: '' }],
          },
        ],
      },
    };

    const result = runControl(distribution, [bucket, distribution]);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-006');
    expect(result!.resourceName).toBe('aws_cloudfront_distribution.site');
    expect(result!.issue).toMatch(/S3 bucket origin/i);
  });

  it('flags an S3 origin (reference form) when origin_access_control_id is omitted entirely and no legacy OAI', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    };

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        origin: [
          {
            origin_id: 's3-origin',
            domain_name: 'aws_s3_bucket.site',
            s3_origin_config: [{}],
          },
        ],
      },
    };

    const result = runControl(distribution, [bucket, distribution]);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-006');
  });

  it('flags an S3 origin identified by literal S3 domain when origin_access_control_id is whitespace-only', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        origin: [
          {
            origin_id: 's3-literal-origin',
            domain_name: 'my-bucket.s3.us-east-1.amazonaws.com',
            origin_access_control_id: '   ',
          },
        ],
      },
    };

    const result = runControl(distribution, [distribution]);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-006');
  });
});
