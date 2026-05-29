import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-003 REQ-06 (Terraform): external log delivery source without paired destination', () => {
  it('flags a distribution when a log_delivery_source references it but no log_delivery_destination exists in the project', () => {
    const distribution = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      values: {
        enabled: true,
        // No logging_config — no inline access logging configured
        default_cache_behavior: [
          {
            target_origin_id: 'origin1',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
        origin: [
          {
            origin_id: 'origin1',
            domain_name: 'example.com',
          },
        ],
      },
    } as unknown as TerraformResource;

    // External log delivery SOURCE referencing the distribution
    const deliverySource = {
      address: 'aws_cloudwatch_log_delivery_source.cf_source',
      type: 'aws_cloudwatch_log_delivery_source',
      name: 'cf_source',
      values: {
        name: 'cloudfront-access-log-source',
        log_type: 'ACCESS_LOGS',
        resource_arn: 'aws_cloudfront_distribution.my_distribution',
      },
    } as unknown as TerraformResource;

    // NOTE: No aws_cloudwatch_log_delivery_destination resource is present.
    // Per strict mode, the chain (source + destination) is incomplete.
    const allResources: TerraformResource[] = [distribution, deliverySource];

    const factory = new Cf003TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = cf003Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-003');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.my_distribution');
    expect(result?.status).toBe('Open');
  });
});
