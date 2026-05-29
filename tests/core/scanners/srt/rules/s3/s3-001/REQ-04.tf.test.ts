import { describe, it, expect } from 'vitest';
import { S3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-04 TF: bucket referenced as log destination is exempt', () => {
  it('passes when bucket has no logging but another logging resource targets it via address reference', () => {
    const logDestinationBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'log_destination',
      address: 'aws_s3_bucket.log_destination',
      values: { bucket: 'my-log-destination-bucket' },
    } as unknown as TerraformResource;

    const appBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'app',
      address: 'aws_s3_bucket.app',
      values: { bucket: 'my-app-bucket' },
    } as unknown as TerraformResource;

    // Reference form: target_bucket = aws_s3_bucket.log_destination.id collapses to address.
    const appLogging: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'app',
      address: 'aws_s3_bucket_logging.app',
      values: {
        bucket: 'aws_s3_bucket.app',
        target_bucket: 'aws_s3_bucket.log_destination',
        target_prefix: 'app-logs/',
      },
    } as unknown as TerraformResource;

    const allResources = [logDestinationBucket, appBucket, appLogging];

    const context: TfContext = {
      projectName: 'test-project',
      resource: logDestinationBucket,
      allResources,
    };

    const factory = new S3001TfAdapterFactory();
    expect(factory.appliesTo('aws_s3_bucket')).toBe(true);

    const adapter = factory.bind(context);
    const control = new S3001Control();
    const result = control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when bucket has no logging but another logging resource targets it via literal bucket name', () => {
    const logDestinationBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'log_destination',
      address: 'aws_s3_bucket.log_destination',
      values: { bucket: 'my-log-destination-bucket' },
    } as unknown as TerraformResource;

    const appBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'app',
      address: 'aws_s3_bucket.app',
      values: { bucket: 'my-app-bucket' },
    } as unknown as TerraformResource;

    // Literal form: target_bucket written as a literal string in HCL.
    const appLogging: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'app',
      address: 'aws_s3_bucket_logging.app',
      values: {
        bucket: 'my-app-bucket',
        target_bucket: 'my-log-destination-bucket',
        target_prefix: 'app-logs/',
      },
    } as unknown as TerraformResource;

    const allResources = [logDestinationBucket, appBucket, appLogging];

    const context: TfContext = {
      projectName: 'test-project',
      resource: logDestinationBucket,
      allResources,
    };

    const factory = new S3001TfAdapterFactory();
    const adapter = factory.bind(context);
    const control = new S3001Control();
    const result = control.run(adapter, context);

    expect(result).toBeNull();
  });
});
