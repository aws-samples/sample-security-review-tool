import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-02 Terraform: S3 bucket with server access logging to a separate destination bucket', () => {
  it('should pass when an aws_s3_bucket_logging resource targets this bucket and points to a different log destination', () => {
    const appBucket: TerraformResource = {
      address: 'aws_s3_bucket.app',
      type: 'aws_s3_bucket',
      name: 'app',
      values: {
        bucket: 'my-app-bucket',
      },
    } as never;

    const logDestinationBucket: TerraformResource = {
      address: 'aws_s3_bucket.logs',
      type: 'aws_s3_bucket',
      name: 'logs',
      values: {
        bucket: 'my-log-destination-bucket',
      },
    } as never;

    const loggingResource: TerraformResource = {
      address: 'aws_s3_bucket_logging.app',
      type: 'aws_s3_bucket_logging',
      name: 'app',
      values: {
        bucket: 'my-app-bucket',
        target_bucket: 'my-log-destination-bucket',
        target_prefix: 'app-logs/',
      },
    } as never;

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
