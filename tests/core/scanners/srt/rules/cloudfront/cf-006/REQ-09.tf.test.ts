import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-09 Terraform: multiple S3 origins where at least one lacks OAC/OAI', () => {
  it('flags when one S3 origin is unprotected even if the others are correctly secured (reference form)', () => {
    const securedBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'secured',
      address: 'aws_s3_bucket.secured',
      values: { bucket: 'secured-bucket' },
    };
    const unsecuredBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'unsecured',
      address: 'aws_s3_bucket.unsecured',
      values: { bucket: 'unsecured-bucket' },
    };
    const legacyBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'legacy',
      address: 'aws_s3_bucket.legacy',
      values: { bucket: 'legacy-bucket' },
    };
    const oac: TerraformResource = {
      type: 'aws_cloudfront_origin_access_control',
      name: 'distro_oac',
      address: 'aws_cloudfront_origin_access_control.distro_oac',
      values: {
        name: 'distro-oac',
        origin_access_control_origin_type: 's3',
        signing_behavior: 'always',
        signing_protocol: 'sigv4',
      },
    };

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            // Properly secured via OAC (reference form — collapsed to address)
            origin_id: 'origin-secured-oac',
            domain_name: 'aws_s3_bucket.secured',
            origin_access_control_id: 'aws_cloudfront_origin_access_control.distro_oac',
            s3_origin_config: [],
          },
          {
            // Properly secured via legacy OAI
            origin_id: 'origin-secured-oai',
            domain_name: 'aws_s3_bucket.legacy',
            s3_origin_config: [
              {
                cloudfront_access_identity_path: 'origin-access-identity/cloudfront/E127EXAMPLE51Z',
              },
            ],
          },
          {
            // UNPROTECTED — no OAC, no OAI
            origin_id: 'origin-unsecured',
            domain_name: 'aws_s3_bucket.unsecured',
            s3_origin_config: [],
          },
        ],
      },
    };

    const allResources = [securedBucket, unsecuredBucket, legacyBucket, oac, distribution];
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
    expect(result?.status).toBe('Open');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.site');
    expect(result?.issue).toMatch(/S3 bucket origin/i);
  });

  it('exposes the unprotected origin id via the adapter while ignoring the secured ones (literal form)', () => {
    const securedBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'secured',
      address: 'aws_s3_bucket.secured',
      values: { bucket: 'secured-bucket' },
    };
    const unsecuredBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'unsecured',
      address: 'aws_s3_bucket.unsecured',
      values: { bucket: 'unsecured-bucket' },
    };
    const oac: TerraformResource = {
      type: 'aws_cloudfront_origin_access_control',
      name: 'distro_oac',
      address: 'aws_cloudfront_origin_access_control.distro_oac',
      values: {
        id: 'EXAMPLEOACID',
        name: 'distro-oac',
        origin_access_control_origin_type: 's3',
        signing_behavior: 'always',
        signing_protocol: 'sigv4',
      },
    };

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            // Properly secured via OAC (literal id form)
            origin_id: 'origin-secured',
            domain_name: 'secured-bucket.s3.us-east-1.amazonaws.com',
            origin_access_control_id: 'EXAMPLEOACID',
            s3_origin_config: [],
          },
          {
            // UNPROTECTED — no OAC, no OAI
            origin_id: 'origin-unsecured',
            domain_name: 'unsecured-bucket.s3.us-east-1.amazonaws.com',
            s3_origin_config: [],
          },
        ],
      },
    };

    const allResources = [securedBucket, unsecuredBucket, oac, distribution];
    const factory = new Cf006TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const adapter = factory.bind(context);
    const unprotected = adapter.findS3OriginsWithoutAccessControl();

    expect(unprotected).toHaveLength(1);
    expect(unprotected[0]?.originId).toBe('origin-unsecured');
  });
});
