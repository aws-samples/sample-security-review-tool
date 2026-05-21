import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-04 (Terraform): bucket referenced as a log destination by another bucket is exempt', () => {
  it('returns no finding for a bucket without logging that is referenced as target_bucket by another aws_s3_bucket_logging', () => {
    const logDestinationBucket: TerraformResource = {
      address: 'aws_s3_bucket.log_destination',
      type: 'aws_s3_bucket',
      name: 'log_destination',
      values: {
        bucket: 'my-log-destination-bucket',
      },
    } as unknown as TerraformResource;

    const appBucket: TerraformResource = {
      address: 'aws_s3_bucket.app',
      type: 'aws_s3_bucket',
      name: 'app',
      values: {
        bucket: 'my-app-bucket',
      },
    } as unknown as TerraformResource;

    const appBucketLogging: TerraformResource = {
      address: 'aws_s3_bucket_logging.app',
      type: 'aws_s3_bucket_logging',
      name: 'app',
      values: {
        bucket: 'my-app-bucket',
        target_bucket: 'my-log-destination-bucket',
        target_prefix: 'logs/',
      },
    } as unknown as TerraformResource;

    const allResources = [logDestinationBucket, appBucket, appBucketLogging];

    const context: TfContext = {
      projectName: 'test-project',
      resource: logDestinationBucket,
      allResources,
    };

    const factory = new S3001TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
