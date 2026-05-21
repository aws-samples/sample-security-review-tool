import { describe, it, expect } from 'vitest';
import { S3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 Terraform - REQ-01: bucket without logging and not a log destination', () => {
  it('flags an aws_s3_bucket that has no aws_s3_bucket_logging configuration and is not referenced as a log destination', () => {
    const bucket: TerraformResource = {
      address: 'aws_s3_bucket.unlogged',
      type: 'aws_s3_bucket',
      name: 'unlogged',
      values: {
        bucket: 'unlogged-bucket',
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [bucket];

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket,
      allResources,
    };

    const factory = new S3001TfAdapterFactory();
    expect(factory.appliesTo('aws_s3_bucket')).toBe(true);

    const adapter = factory.bind(context);
    const control = new S3001Control();
    const result = control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('S3-001');
    expect(result!.resourceName).toBe('aws_s3_bucket.unlogged');
    expect(result!.resourceType).toBe('aws_s3_bucket');
    expect(result!.status).toBe('Open');
    expect(result!.priority).toBe('HIGH');
  });
});
