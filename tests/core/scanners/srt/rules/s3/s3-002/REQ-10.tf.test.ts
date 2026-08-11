import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(resource: TerraformResource, allResources: TerraformResource[] = [resource]): TfContext {
  return {
    projectName: 'test-project',
    resource,
    allResources,
  };
}

describe('S3-002 Terraform - allow statement without principal', () => {
  it('passes when an Allow statement omits the Principal element (invalid IAM grant, no principal receives access)', () => {
    const policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          // Principal intentionally omitted
        },
      ],
    };

    const bucketPolicy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'site',
      address: 'aws_s3_bucket_policy.site',
      values: {
        bucket: 'aws_s3_bucket.site',
        policy: JSON.stringify(policyDocument),
      },
    } as unknown as TerraformResource;

    const context = buildContext(bucketPolicy);
    const factory = new S3002TfAdapterFactory();
    const adapter = factory.bind(context);

    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
