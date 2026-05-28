import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 Terraform - REQ-01', () => {
  it('flags an S3-origin distribution that has neither origin_access_control_id nor s3_origin_config.origin_access_identity', () => {
    const distribution = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'S3Origin',
            domain_name: 'my-bucket.s3.amazonaws.com',
            // No origin_access_control_id
            s3_origin_config: [
              {
                // Empty / no origin_access_identity (legacy OAI)
                origin_access_identity: '',
              },
            ],
          },
        ],
        default_cache_behavior: [
          {
            target_origin_id: 'S3Origin',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
      },
    } as any;

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };

    const factory = new Cf006TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);
    const adapter = factory.bind(context);

    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.my_distribution');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });
});
