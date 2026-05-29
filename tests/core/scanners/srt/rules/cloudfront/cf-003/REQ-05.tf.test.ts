import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-003 REQ-05 (Terraform): External delivery source + destination references distribution', () => {
  it('passes (no finding) when an aws_cloudwatch_log_delivery_source references the distribution and is paired with a delivery destination', () => {
    const distribution = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      values: {
        enabled: true,
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
        // No logging_config -> no inline access logging
      },
    } as unknown as TerraformResource;

    const deliveryDestination = {
      address: 'aws_cloudwatch_log_delivery_destination.my_dest',
      type: 'aws_cloudwatch_log_delivery_destination',
      name: 'my_dest',
      values: {
        name: 'cf-access-logs-destination',
        delivery_destination_type: 'CWL',
        delivery_destination_configuration: [
          {
            destination_resource_arn: 'arn:aws:logs:us-east-1:123456789012:log-group:cf-logs',
          },
        ],
      },
    } as unknown as TerraformResource;

    const deliverySource = {
      address: 'aws_cloudwatch_log_delivery_source.my_source',
      type: 'aws_cloudwatch_log_delivery_source',
      name: 'my_source',
      values: {
        name: 'cf-access-logs-source',
        log_type: 'ACCESS_LOGS',
        // Reference to the distribution's address (e.g. ${aws_cloudfront_distribution.my_distribution.arn})
        resource_arn: 'aws_cloudfront_distribution.my_distribution',
      },
    } as unknown as TerraformResource;

    const delivery = {
      address: 'aws_cloudwatch_log_delivery.my_delivery',
      type: 'aws_cloudwatch_log_delivery',
      name: 'my_delivery',
      values: {
        delivery_source_name: 'cf-access-logs-source',
        delivery_destination_arn: 'arn:aws:logs:us-east-1:123456789012:delivery-destination:cf-access-logs-destination',
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [
      distribution,
      deliveryDestination,
      deliverySource,
      delivery,
    ];

    const factory = new Cf003TfAdapterFactory();
    expect(factory.appliesTo(distribution.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const adapter = factory.bind(context);
    expect(adapter.hasAccessLogging).toBe(true);

    const result = cf003Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
