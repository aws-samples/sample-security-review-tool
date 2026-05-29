import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-003 REQ-07 (Terraform): delivery source references a different distribution', () => {
  it('flags the assessed distribution when the only delivery source targets a different distribution', () => {
    const assessedDistribution = {
      address: 'aws_cloudfront_distribution.assessed',
      type: 'aws_cloudfront_distribution',
      name: 'assessed',
      values: {
        enabled: true,
        // No logging_config block
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

    const otherDistribution = {
      address: 'aws_cloudfront_distribution.other',
      type: 'aws_cloudfront_distribution',
      name: 'other',
      values: {
        enabled: true,
        default_cache_behavior: [
          {
            target_origin_id: 'origin2',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
        origin: [
          {
            origin_id: 'origin2',
            domain_name: 'other.example.com',
          },
        ],
      },
    } as unknown as TerraformResource;

    // Delivery source references the OTHER distribution's address, not the assessed one
    const deliverySourceForOther = {
      address: 'aws_cloudwatch_log_delivery_source.other_src',
      type: 'aws_cloudwatch_log_delivery_source',
      name: 'other_src',
      values: {
        name: 'cloudfront-logs-other',
        resource_arn: 'aws_cloudfront_distribution.other',
        log_type: 'ACCESS_LOGS',
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [
      assessedDistribution,
      otherDistribution,
      deliverySourceForOther,
    ];

    const factory = new Cf003TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: assessedDistribution,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = cf003Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-003');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.assessed');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.status).toBe('Open');
  });
});
