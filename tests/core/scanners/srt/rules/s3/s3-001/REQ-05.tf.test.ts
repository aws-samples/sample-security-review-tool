import { describe, it, expect } from 'vitest';
import { S3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-05 (Terraform): bucket appears intended as a log destination but no other bucket references it', () => {
  it('flags a bucket whose name and policy suggest it is a log destination, when no aws_s3_bucket_logging targets it', () => {
    // The bucket has a "log destination"-ish name and a bucket policy granting
    // the S3 logging service principal write access. These are heuristic hints
    // of intent but are NOT sufficient evidence per the rule's rationale.
    const accessLogsBucket = {
      address: 'aws_s3_bucket.access_logs',
      type: 'aws_s3_bucket',
      name: 'access_logs',
      values: {
        bucket: 'my-app-access-logs',
      },
    } as unknown as TerraformResource;

    const accessLogsBucketPolicy = {
      address: 'aws_s3_bucket_policy.access_logs',
      type: 'aws_s3_bucket_policy',
      name: 'access_logs',
      values: {
        bucket: 'my-app-access-logs',
        policy: JSON.stringify({
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { Service: 'logging.s3.amazonaws.com' },
              Action: 's3:PutObject',
              Resource: 'arn:aws:s3:::my-app-access-logs/*',
            },
          ],
        }),
      },
    } as unknown as TerraformResource;

    // An unrelated bucket that does NOT reference my-app-access-logs as its target_bucket.
    const unrelatedBucket = {
      address: 'aws_s3_bucket.unrelated',
      type: 'aws_s3_bucket',
      name: 'unrelated',
      values: {
        bucket: 'unrelated-bucket',
      },
    } as unknown as TerraformResource;

    const allResources = [accessLogsBucket, accessLogsBucketPolicy, unrelatedBucket];

    const factory = new S3001TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: accessLogsBucket,
      allResources,
    };

    const adapter = factory.bind(context);
    const control = new S3001Control();
    const result = control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-001');
    expect(result?.resourceName).toBe('aws_s3_bucket.access_logs');
    expect(result?.resourceType).toBe('aws_s3_bucket');
    expect(result?.status).toBe('Open');
  });
});
