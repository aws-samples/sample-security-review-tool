import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 / REQ-09 (Terraform): logging configured with destination bucket and log file prefix', () => {
  it('passes when aws_s3_bucket_logging references the bucket and a target_bucket plus a target_prefix (literal form)', () => {
    const appBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'app',
      address: 'aws_s3_bucket.app',
      values: { bucket: 'my-app-bucket' },
    } as unknown as TerraformResource;

    const logsBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'logs',
      address: 'aws_s3_bucket.logs',
      values: { bucket: 'my-logs-bucket' },
    } as unknown as TerraformResource;

    const logging: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'app',
      address: 'aws_s3_bucket_logging.app',
      values: {
        bucket: 'my-app-bucket',
        target_bucket: 'my-logs-bucket',
        target_prefix: 'access-logs/',
      },
    } as unknown as TerraformResource;

    const allResources = [appBucket, logsBucket, logging];

    const factory = new S3001TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: appBucket,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when aws_s3_bucket_logging references the bucket and a target_bucket plus a target_prefix (reference form)', () => {
    const appBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'app',
      address: 'aws_s3_bucket.app',
      values: { bucket: 'my-app-bucket' },
    } as unknown as TerraformResource;

    const logsBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'logs',
      address: 'aws_s3_bucket.logs',
      values: { bucket: 'my-logs-bucket' },
    } as unknown as TerraformResource;

    const logging: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'app',
      address: 'aws_s3_bucket_logging.app',
      values: {
        bucket: 'aws_s3_bucket.app',
        target_bucket: 'aws_s3_bucket.logs',
        target_prefix: 'access-logs/',
      },
    } as unknown as TerraformResource;

    const allResources = [appBucket, logsBucket, logging];

    const factory = new S3001TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: appBucket,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
