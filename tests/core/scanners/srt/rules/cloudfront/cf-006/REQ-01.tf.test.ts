import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 / Terraform / REQ-01', () => {
  it('flags a distribution with an S3 origin that has no OAC and no legacy OAI (reference form)', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'origin',
      address: 'aws_s3_bucket.origin',
      values: {
        bucket: 'my-origin-bucket',
      },
    } as TerraformResource;

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-origin',
            // Reference form — collapsed to the bucket's address
            domain_name: 'aws_s3_bucket.origin',
            // No origin_access_control_id (no OAC)
            // No s3_origin_config block (no legacy OAI)
          },
        ],
        default_cache_behavior: [
          {
            target_origin_id: 's3-origin',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
      },
    } as TerraformResource;

    const factory = new Cf006TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [bucket, distribution],
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-006');
    expect(result!.resourceType).toBe('aws_cloudfront_distribution');
    expect(result!.resourceName).toBe('aws_cloudfront_distribution.site');
    expect(result!.status).toBe('Open');
  });

  it('flags a distribution with an S3 origin referenced by literal bucket name with no OAC and no legacy OAI', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'origin',
      address: 'aws_s3_bucket.origin',
      values: {
        bucket: 'my-origin-bucket',
      },
    } as TerraformResource;

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-origin',
            // Literal form — user wrote the regional domain name directly
            domain_name: 'my-origin-bucket.s3.us-east-1.amazonaws.com',
          },
        ],
        default_cache_behavior: [
          {
            target_origin_id: 's3-origin',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
      },
    } as TerraformResource;

    const factory = new Cf006TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [bucket, distribution],
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-006');
  });
});
