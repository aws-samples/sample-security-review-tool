import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Cf003TfAdapterFactory();

function runControl(allResources: TerraformResource[], targetAddress: string) {
  const resource = allResources.find(r => r.address === targetAddress)!;
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  const adapter = factory.bind(context);
  return cf003Control.run(adapter, context);
}

describe('CF-003 Terraform - REQ-09: multiple logging configurations with at least one fully valid', () => {
  it('passes when both inline logging_config AND external delivery chain are present and valid', () => {
    const distributionAddress = 'aws_cloudfront_distribution.my_distribution';
    const resources: TerraformResource[] = [
      {
        address: distributionAddress,
        type: 'aws_cloudfront_distribution',
        name: 'my_distribution',
        values: {
          enabled: true,
          logging_config: [
            {
              bucket: 'my-logs-bucket.s3.amazonaws.com',
              prefix: 'cf-logs/',
              include_cookies: false,
            },
          ],
        },
      } as unknown as TerraformResource,
      {
        address: 'aws_cloudwatch_log_delivery_source.my_source',
        type: 'aws_cloudwatch_log_delivery_source',
        name: 'my_source',
        values: {
          name: 'my-source',
          resource_arn: distributionAddress,
          log_type: 'ACCESS_LOGS',
        },
      } as unknown as TerraformResource,
      {
        address: 'aws_cloudwatch_log_delivery_destination.my_destination',
        type: 'aws_cloudwatch_log_delivery_destination',
        name: 'my_destination',
        values: {
          name: 'my-destination',
        },
      } as unknown as TerraformResource,
    ];

    const result = runControl(resources, distributionAddress);
    expect(result).toBeNull();
  });

  it('passes when inline logging_config is valid but external delivery chain is incomplete (missing destination)', () => {
    const distributionAddress = 'aws_cloudfront_distribution.my_distribution';
    const resources: TerraformResource[] = [
      {
        address: distributionAddress,
        type: 'aws_cloudfront_distribution',
        name: 'my_distribution',
        values: {
          enabled: true,
          logging_config: [
            {
              bucket: 'my-logs-bucket.s3.amazonaws.com',
              prefix: 'cf-logs/',
            },
          ],
        },
      } as unknown as TerraformResource,
      {
        address: 'aws_cloudwatch_log_delivery_source.my_source',
        type: 'aws_cloudwatch_log_delivery_source',
        name: 'my_source',
        values: {
          name: 'my-source',
          resource_arn: distributionAddress,
          log_type: 'ACCESS_LOGS',
        },
      } as unknown as TerraformResource,
      // No delivery destination - external chain is incomplete
    ];

    const result = runControl(resources, distributionAddress);
    expect(result).toBeNull();
  });

  it('passes when inline logging_config is invalid (missing bucket) but external delivery chain is complete', () => {
    const distributionAddress = 'aws_cloudfront_distribution.my_distribution';
    const resources: TerraformResource[] = [
      {
        address: distributionAddress,
        type: 'aws_cloudfront_distribution',
        name: 'my_distribution',
        values: {
          enabled: true,
          logging_config: [
            {
              // bucket missing - inline logging invalid
              prefix: 'cf-logs/',
              include_cookies: false,
            },
          ],
        },
      } as unknown as TerraformResource,
      {
        address: 'aws_cloudwatch_log_delivery_source.my_source',
        type: 'aws_cloudwatch_log_delivery_source',
        name: 'my_source',
        values: {
          name: 'my-source',
          resource_arn: distributionAddress,
          log_type: 'ACCESS_LOGS',
        },
      } as unknown as TerraformResource,
      {
        address: 'aws_cloudwatch_log_delivery_destination.my_destination',
        type: 'aws_cloudwatch_log_delivery_destination',
        name: 'my_destination',
        values: {
          name: 'my-destination',
        },
      } as unknown as TerraformResource,
    ];

    const result = runControl(resources, distributionAddress);
    expect(result).toBeNull();
  });
});
