import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 / REQ-06 (Terraform): dangling origin_access_control_id reference', () => {
  it('flags an S3 origin whose origin_access_control_id does not resolve to an OAC resource in the plan (reference form)', () => {
    // The plan reader has collapsed the origin_access_control_id expression
    // to the address string "aws_cloudfront_origin_access_control.missing".
    // No resource with that address exists in allResources, so the reference
    // dangles. Per the resolved decision, this must be flagged.
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    } as TerraformResource;

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'site-s3-origin',
            // Reference form: collapsed from aws_s3_bucket.site.bucket_regional_domain_name
            domain_name: 'aws_s3_bucket.site',
            // Reference form: collapsed from
            // aws_cloudfront_origin_access_control.missing.id — but no such
            // resource is in the plan.
            origin_access_control_id: 'aws_cloudfront_origin_access_control.missing',
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [bucket, distribution];

    const factory = new Cf006TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.site');
    expect(result?.status).toBe('Open');
  });

  it('flags an S3 origin whose origin_access_control_id is a literal string not matching any OAC resource (literal form)', () => {
    // Literal form: the user wrote a hard-coded OAC id string in HCL that
    // does not correspond to any aws_cloudfront_origin_access_control
    // resource managed in the plan.
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    } as TerraformResource;

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'site-s3-origin',
            domain_name: 'my-site-bucket',
            origin_access_control_id: 'E1234NOTINPLAN',
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [bucket, distribution];

    const factory = new Cf006TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
  });
});
