import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 Terraform - REQ-08: lifecycle rule status unresolved', () => {
  it('passes when the only lifecycle rule has an unresolved status (known-after-apply / undefined) - cannot conclusively determine no enabled rule exists', () => {
    const bucket: TerraformResource = {
      address: 'aws_s3_bucket.my_bucket',
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      values: {
        bucket: 'my-bucket',
        id: 'my-bucket',
      },
    } as unknown as TerraformResource;

    const lifecycle: TerraformResource = {
      address: 'aws_s3_bucket_lifecycle_configuration.my_bucket',
      type: 'aws_s3_bucket_lifecycle_configuration',
      name: 'my_bucket',
      values: {
        bucket: 'my-bucket',
        rule: [
          {
            id: 'expire-old-objects',
            // status is unresolvable at analysis time (e.g., known-after-apply) - represented as undefined
            status: undefined,
            expiration: [{ days: 30 }],
          },
        ],
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket,
      allResources: [bucket, lifecycle],
    };

    const factory = new S3008TfAdapterFactory();
    expect(factory.appliesTo('aws_s3_bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
