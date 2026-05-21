import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 Terraform - REQ-09: Lifecycle configuration on a different bucket does not cover the assessed bucket', () => {
  it('flags the assessed bucket when an aws_s3_bucket_lifecycle_configuration references a different bucket', () => {
    const otherBucket: TerraformResource = {
      address: 'aws_s3_bucket.other',
      type: 'aws_s3_bucket',
      name: 'other',
      values: {
        bucket: 'other-bucket',
        id: 'other-bucket',
      },
    } as TerraformResource;

    const assessedBucket: TerraformResource = {
      address: 'aws_s3_bucket.assessed',
      type: 'aws_s3_bucket',
      name: 'assessed',
      values: {
        bucket: 'assessed-bucket',
        id: 'assessed-bucket',
      },
    } as TerraformResource;

    // Lifecycle configuration is attached to "other-bucket", NOT the assessed bucket
    const lifecycleForOther: TerraformResource = {
      address: 'aws_s3_bucket_lifecycle_configuration.other',
      type: 'aws_s3_bucket_lifecycle_configuration',
      name: 'other',
      values: {
        bucket: 'other-bucket',
        rule: [
          {
            id: 'ExpireOldObjects',
            status: 'Enabled',
            expiration: [{ days: 365 }],
          },
        ],
      },
    } as TerraformResource;

    const allResources: TerraformResource[] = [otherBucket, assessedBucket, lifecycleForOther];

    const context: TfContext = {
      projectName: 'test-project',
      resource: assessedBucket,
      allResources,
    };

    const factory = new S3008TfAdapterFactory();
    expect(factory.appliesTo(assessedBucket.type)).toBe(true);

    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('S3-008');
    expect(result!.resourceName).toBe('aws_s3_bucket.assessed');
    expect(result!.resourceType).toBe('aws_s3_bucket');
    expect(result!.status).toBe('Open');
    expect(result!.priority).toBe('HIGH');
  });
});
