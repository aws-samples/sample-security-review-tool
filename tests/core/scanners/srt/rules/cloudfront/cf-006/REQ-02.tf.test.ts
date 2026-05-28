import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-02 (Terraform): S3 origin references in-template OAC by identifier', () => {
  it('passes when the S3 origin has origin_access_control_id resolved from an in-template OAC resource', () => {
    const oacResource = {
      address: 'aws_cloudfront_origin_access_control.example',
      type: 'aws_cloudfront_origin_access_control',
      name: 'example',
      mode: 'managed',
      values: {
        name: 'my-oac',
        origin_access_control_origin_type: 's3',
        signing_behavior: 'always',
        signing_protocol: 'sigv4',
        id: 'EXAMPLE_OAC_ID',
      },
    } as unknown as TerraformResource;

    const distributionResource = {
      address: 'aws_cloudfront_distribution.example',
      type: 'aws_cloudfront_distribution',
      name: 'example',
      mode: 'managed',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-origin',
            domain_name: 'my-bucket.s3.us-east-1.amazonaws.com',
            // Reference to aws_cloudfront_origin_access_control.example.id resolved by Terraform plan
            origin_access_control_id: 'EXAMPLE_OAC_ID',
            s3_origin_config: [],
          },
        ],
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: distributionResource,
      allResources: [distributionResource, oacResource],
    };

    const factory = new Cf006TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(adapter.unprotectedS3Origins).toEqual([]);
    expect(result).toBeNull();
  });
});
