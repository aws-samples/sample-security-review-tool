import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 Terraform - REQ-09: bucket with logging configuration including destination and prefix', () => {
  it('passes (returns null) when an aws_s3_bucket_logging resource targets the bucket with both target_bucket and target_prefix', () => {
    const appBucket: TerraformResource = {
      address: 'aws_s3_bucket.app',
      type: 'aws_s3_bucket',
      name: 'app',
      values: {
        bucket: 'app-bucket',
      },
    } as unknown as TerraformResource;

    const logDestinationBucket: TerraformResource = {
      address: 'aws_s3_bucket.log_destination',
      type: 'aws_s3_bucket',
      name: 'log_destination',
      values: {
        bucket: 'log-destination-bucket',
      },
    } as unknown as TerraformResource;

    const loggingResource: TerraformResource = {
      address: 'aws_s3_bucket_logging.app',
      type: 'aws_s3_bucket_logging',
      name: 'app',
      values: {
        bucket: 'app-bucket',
        target_bucket: 'log-destination-bucket',
        target_prefix: 'access-logs/',
      },
    } as unknown as TerraformResource;

    const allResources = [appBucket, logDestinationBucket, loggingResource];

    const context: TfContext = {
      projectName: 'test-project',
      resource: appBucket,
      allResources,
    };

    const factory = new S3001TfAdapterFactory();
    expect(factory.appliesTo('aws_s3_bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
