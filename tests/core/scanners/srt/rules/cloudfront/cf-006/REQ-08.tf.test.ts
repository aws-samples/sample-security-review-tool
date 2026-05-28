import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 Terraform - REQ-08: multi-origin distribution with all S3 origins protected by OAC and remaining origins non-OAC-eligible', () => {
  it('passes when every S3 origin has a resolved OAC reference and other origins are custom HTTP origins', () => {
    const oacOne: TerraformResource = {
      address: 'aws_cloudfront_origin_access_control.s3_oac_one',
      type: 'aws_cloudfront_origin_access_control',
      name: 's3_oac_one',
      values: {
        id: 'OAC123ABC',
        name: 'oac-one',
        origin_access_control_origin_type: 's3',
        signing_behavior: 'always',
        signing_protocol: 'sigv4',
      },
    } as unknown as TerraformResource;

    const oacTwo: TerraformResource = {
      address: 'aws_cloudfront_origin_access_control.s3_oac_two',
      type: 'aws_cloudfront_origin_access_control',
      name: 's3_oac_two',
      values: {
        id: 'OAC456DEF',
        name: 'oac-two',
        origin_access_control_origin_type: 's3',
        signing_behavior: 'always',
        signing_protocol: 'sigv4',
      },
    } as unknown as TerraformResource;

    const distribution: TerraformResource = {
      address: 'aws_cloudfront_distribution.dist',
      type: 'aws_cloudfront_distribution',
      name: 'dist',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-origin-one',
            domain_name: 'bucket-one.s3.us-east-1.amazonaws.com',
            s3_origin_config: [{}],
            origin_access_control_id: 'OAC123ABC',
          },
          {
            origin_id: 's3-origin-two',
            domain_name: 'bucket-two.s3.us-east-1.amazonaws.com',
            s3_origin_config: [{}],
            origin_access_control_id: 'OAC456DEF',
          },
          {
            origin_id: 'custom-http-origin',
            domain_name: 'api.example.com',
            custom_origin_config: [
              {
                origin_protocol_policy: 'https-only',
                http_port: 80,
                https_port: 443,
              },
            ],
          },
          {
            origin_id: 'another-custom-http-origin',
            domain_name: 'legacy.example.org',
            custom_origin_config: [
              {
                origin_protocol_policy: 'https-only',
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [oacOne, oacTwo, distribution];

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const factory = new Cf006TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(adapter.unprotectedS3Origins).toEqual([]);
    expect(result).toBeNull();
  });
});
