import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-08 Terraform: empty logging configuration block', () => {
  it('flags an aws_s3_bucket with an empty logging block and no external aws_s3_bucket_logging resource', () => {
    const bucketResource = {
      address: 'aws_s3_bucket.my_bucket',
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      values: {
        bucket: 'my-bucket',
        logging: [],
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [bucketResource];

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucketResource,
      allResources,
    };

    const factory = new S3001TfAdapterFactory();
    expect(factory.appliesTo('aws_s3_bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('S3-001');
    expect(result!.resourceName).toBe('aws_s3_bucket.my_bucket');
    expect(result!.resourceType).toBe('aws_s3_bucket');
    expect(result!.status).toBe('Open');
    expect(result!.priority).toBe('HIGH');
  });
});
