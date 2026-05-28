import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 Terraform - REQ-14: S3 origin with OAC having wildcard/generic signing config', () => {
  it('passes when an S3 origin references an OAC resource that has a generic/wildcard signing+origin-type configuration', () => {
    // The OAC has generic/wildcard-style internal config (no-override behavior, generic origin type).
    // The rule should NOT inspect these internal fields; it only verifies that the
    // origin_access_control_id resolves to a known aws_cloudfront_origin_access_control resource.
    const oacResource = {
      type: 'aws_cloudfront_origin_access_control',
      address: 'aws_cloudfront_origin_access_control.generic_oac',
      name: 'generic_oac',
      mode: 'managed',
      values: {
        id: 'oac-generic-id-123',
        name: 'generic-oac',
        signing_behavior: 'no-override',
        signing_protocol: 'sigv4',
        origin_access_control_origin_type: 's3',
      },
    } as unknown as TerraformResource;

    const distributionResource = {
      type: 'aws_cloudfront_distribution',
      address: 'aws_cloudfront_distribution.this',
      name: 'this',
      mode: 'managed',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-origin',
            domain_name: 'my-bucket.s3.us-east-1.amazonaws.com',
            origin_access_control_id: 'oac-generic-id-123',
            s3_origin_config: [{}],
          },
        ],
      },
    } as unknown as TerraformResource;

    const factory = new Cf006TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distributionResource,
      allResources: [distributionResource, oacResource],
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(adapter.unprotectedS3Origins).toHaveLength(0);
    expect(adapter.unprotectedOacEligibleOrigins).toHaveLength(0);
    expect(result).toBeNull();
  });
});
