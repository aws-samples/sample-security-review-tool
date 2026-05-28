import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-07 (Terraform): S3 origin with legacy OAI and dangling OAC reference', () => {
  it('passes because the valid OAI supersedes the dangling OAC reference', () => {
    const distribution = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      mode: 'managed',
      values: {
        origin: [
          {
            origin_id: 's3-origin-1',
            domain_name: 'my-bucket.s3.us-east-1.amazonaws.com',
            s3_origin_config: [
              {
                origin_access_identity: 'origin-access-identity/cloudfront/E1234567890ABC',
              },
            ],
            origin_access_control_id: 'oac-nonexistent-12345',
          },
        ],
      },
    } as unknown as TerraformResource;

    // Note: there is intentionally no aws_cloudfront_origin_access_control
    // resource in allResources whose id matches 'oac-nonexistent-12345',
    // making the OAC reference dangling.
    const allResources: TerraformResource[] = [distribution];

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
