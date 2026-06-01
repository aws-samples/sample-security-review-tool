import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 Terraform - custom origin to S3 website endpoint with HTTP-only', () => {
  it('flags a custom origin (literal domain) that uses http-only protocol policy even when pointing at an S3 static website endpoint', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-website-origin',
            // Literal S3 static website hosting endpoint
            domain_name: 'sitebucket.s3-website-us-east-1.amazonaws.com',
            custom_origin_config: [
              {
                // S3 website endpoints only support HTTP, but rule must still flag.
                origin_protocol_policy: 'http-only',
                http_port: 80,
                https_port: 443,
                origin_ssl_protocols: ['TLSv1.2'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const factory = new Cf005TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };

    const adapter = factory.bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-005');
    expect(result!.resourceType).toBe('aws_cloudfront_distribution');
    expect(result!.resourceName).toBe('aws_cloudfront_distribution.site');
    expect(result!.status).toBe('Open');
    expect(result!.issue).toMatch(/HTTP/i);
  });

  it('flags a custom origin (reference form) that points at an S3 bucket website endpoint via reference and uses http-only', () => {
    // Reference form: domain_name was something like aws_s3_bucket.site.website_endpoint
    // and is collapsed by the plan reader to the bucket's address string.
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-website-origin',
            domain_name: 'aws_s3_bucket.site',
            custom_origin_config: [
              {
                origin_protocol_policy: 'http-only',
                http_port: 80,
                https_port: 443,
                origin_ssl_protocols: ['TLSv1.2'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const factory = new Cf005TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };

    const adapter = factory.bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-005');
    expect(result!.issue).toMatch(/HTTP/i);
  });
});
