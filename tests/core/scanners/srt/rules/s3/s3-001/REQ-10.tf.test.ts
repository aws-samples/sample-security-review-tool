import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 Terraform - REQ-10: bucket referenced as log destination by multiple other buckets', () => {
  it('passes when the bucket has no logging configuration but is the target_bucket for multiple aws_s3_bucket_logging resources', () => {
    const centralLogBucket: TerraformResource = {
      address: 'aws_s3_bucket.central_log_bucket',
      type: 'aws_s3_bucket',
      name: 'central_log_bucket',
      values: {
        bucket: 'central-log-bucket',
      },
    } as unknown as TerraformResource;

    const appBucketOne: TerraformResource = {
      address: 'aws_s3_bucket.app_one',
      type: 'aws_s3_bucket',
      name: 'app_one',
      values: {
        bucket: 'app-bucket-one',
      },
    } as unknown as TerraformResource;

    const appBucketTwo: TerraformResource = {
      address: 'aws_s3_bucket.app_two',
      type: 'aws_s3_bucket',
      name: 'app_two',
      values: {
        bucket: 'app-bucket-two',
      },
    } as unknown as TerraformResource;

    const appBucketThree: TerraformResource = {
      address: 'aws_s3_bucket.app_three',
      type: 'aws_s3_bucket',
      name: 'app_three',
      values: {
        bucket: 'app-bucket-three',
      },
    } as unknown as TerraformResource;

    const loggingOne: TerraformResource = {
      address: 'aws_s3_bucket_logging.app_one',
      type: 'aws_s3_bucket_logging',
      name: 'app_one',
      values: {
        bucket: 'app-bucket-one',
        target_bucket: 'central-log-bucket',
        target_prefix: 'app-one/',
      },
    } as unknown as TerraformResource;

    const loggingTwo: TerraformResource = {
      address: 'aws_s3_bucket_logging.app_two',
      type: 'aws_s3_bucket_logging',
      name: 'app_two',
      values: {
        bucket: 'app-bucket-two',
        target_bucket: 'central-log-bucket',
        target_prefix: 'app-two/',
      },
    } as unknown as TerraformResource;

    const loggingThree: TerraformResource = {
      address: 'aws_s3_bucket_logging.app_three',
      type: 'aws_s3_bucket_logging',
      name: 'app_three',
      values: {
        bucket: 'app-bucket-three',
        target_bucket: 'central-log-bucket',
        target_prefix: 'app-three/',
      },
    } as unknown as TerraformResource;

    const allResources = [
      centralLogBucket,
      appBucketOne,
      appBucketTwo,
      appBucketThree,
      loggingOne,
      loggingTwo,
      loggingThree,
    ];

    const context: TfContext = {
      projectName: 'test-project',
      resource: centralLogBucket,
      allResources,
    };

    const factory = new S3001TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
