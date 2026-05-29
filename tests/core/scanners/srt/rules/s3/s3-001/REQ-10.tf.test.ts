import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 Terraform - REQ-10: bucket referenced as log destination by multiple buckets', () => {
  it('passes when an S3 bucket has no logging config but is the log destination for multiple other buckets (reference form)', () => {
    const centralLogsBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'central_logs',
      address: 'aws_s3_bucket.central_logs',
      values: { bucket: 'central-logs-bucket' },
    } as unknown as TerraformResource;

    const appBucketOne: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'app_one',
      address: 'aws_s3_bucket.app_one',
      values: { bucket: 'app-one-bucket' },
    } as unknown as TerraformResource;

    const appBucketTwo: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'app_two',
      address: 'aws_s3_bucket.app_two',
      values: { bucket: 'app-two-bucket' },
    } as unknown as TerraformResource;

    const appBucketThree: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'app_three',
      address: 'aws_s3_bucket.app_three',
      values: { bucket: 'app-three-bucket' },
    } as unknown as TerraformResource;

    const loggingOne: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'app_one_logging',
      address: 'aws_s3_bucket_logging.app_one_logging',
      values: {
        bucket: 'aws_s3_bucket.app_one',
        target_bucket: 'aws_s3_bucket.central_logs',
      },
    } as unknown as TerraformResource;

    const loggingTwo: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'app_two_logging',
      address: 'aws_s3_bucket_logging.app_two_logging',
      values: {
        bucket: 'aws_s3_bucket.app_two',
        target_bucket: 'aws_s3_bucket.central_logs',
      },
    } as unknown as TerraformResource;

    const loggingThree: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'app_three_logging',
      address: 'aws_s3_bucket_logging.app_three_logging',
      values: {
        bucket: 'aws_s3_bucket.app_three',
        target_bucket: 'aws_s3_bucket.central_logs',
      },
    } as unknown as TerraformResource;

    const allResources = [
      centralLogsBucket,
      appBucketOne,
      appBucketTwo,
      appBucketThree,
      loggingOne,
      loggingTwo,
      loggingThree,
    ];

    const context: TfContext = {
      projectName: 'test-project',
      resource: centralLogsBucket,
      allResources,
    };

    const factory = new S3001TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when the log destination relationship is wired with literal bucket names (literal form)', () => {
    const centralLogsBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'central_logs',
      address: 'aws_s3_bucket.central_logs',
      values: { bucket: 'central-logs-bucket' },
    } as unknown as TerraformResource;

    const appBucketOne: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'app_one',
      address: 'aws_s3_bucket.app_one',
      values: { bucket: 'app-one-bucket' },
    } as unknown as TerraformResource;

    const appBucketTwo: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'app_two',
      address: 'aws_s3_bucket.app_two',
      values: { bucket: 'app-two-bucket' },
    } as unknown as TerraformResource;

    const loggingOne: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'app_one_logging',
      address: 'aws_s3_bucket_logging.app_one_logging',
      values: {
        bucket: 'app-one-bucket',
        target_bucket: 'central-logs-bucket',
      },
    } as unknown as TerraformResource;

    const loggingTwo: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'app_two_logging',
      address: 'aws_s3_bucket_logging.app_two_logging',
      values: {
        bucket: 'app-two-bucket',
        target_bucket: 'central-logs-bucket',
      },
    } as unknown as TerraformResource;

    const allResources = [centralLogsBucket, appBucketOne, appBucketTwo, loggingOne, loggingTwo];

    const context: TfContext = {
      projectName: 'test-project',
      resource: centralLogsBucket,
      allResources,
    };

    const factory = new S3001TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
