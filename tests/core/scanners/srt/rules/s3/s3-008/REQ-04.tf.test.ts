import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 REQ-04 (Terraform): bucket has lifecycle configuration with both enabled and disabled rules', () => {
  it('passes when at least one rule is enabled even if other rules are disabled', () => {
    const bucket: TerraformResource = {
      address: 'aws_s3_bucket.my_bucket',
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      values: {
        bucket: 'my-bucket-name',
        id: 'my-bucket-name',
      },
    } as unknown as TerraformResource;

    const lifecycle: TerraformResource = {
      address: 'aws_s3_bucket_lifecycle_configuration.my_bucket_lc',
      type: 'aws_s3_bucket_lifecycle_configuration',
      name: 'my_bucket_lc',
      values: {
        bucket: 'my-bucket-name',
        rule: [
          {
            id: 'EnabledRule',
            status: 'Enabled',
            expiration: [{ days: 365 }],
          },
          {
            id: 'DisabledRule',
            status: 'Disabled',
            expiration: [{ days: 30 }],
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources = [bucket, lifecycle];

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket,
      allResources,
    };

    const factory = new S3008TfAdapterFactory();
    expect(factory.appliesTo('aws_s3_bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
