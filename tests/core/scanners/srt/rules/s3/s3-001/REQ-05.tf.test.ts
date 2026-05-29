import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (Terraform):
 * An S3 bucket has no logging configuration but appears intended as a log destination
 * (e.g., by name or by a bucket policy granting the S3 logging service principal write
 * access), without any other bucket in the plan explicitly referencing it as a target.
 *
 * Expected: FLAG. Naming heuristics and policy hints are NOT sufficient evidence to
 * exempt a bucket from the server access logging requirement. Only an explicit
 * reference from another aws_s3_bucket_logging.target_bucket grants the exemption.
 *
 * This test uses the reference form (target_bucket pointing at an aws_s3_bucket address)
 * as required by the project test idiom for SPECIFIC_RESOURCE-style requirements.
 */
describe('S3-001 [TF] REQ-05: bucket appears intended as log destination by name/policy only -> flag', () => {
  it('flags a bucket whose name suggests "logs" when no aws_s3_bucket_logging targets it', () => {
    // The "log destination looking" bucket - no logging configured on itself,
    // and nothing in the plan targets it as a log destination.
    const accessLogsBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'access_logs',
      address: 'aws_s3_bucket.access_logs',
      values: {
        bucket: 'my-app-access-logs',
      },
    } as unknown as TerraformResource;

    // A bucket policy granting the S3 logging service principal write access.
    // This is a hint about intent but is NOT considered by the rule.
    const accessLogsBucketPolicy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'access_logs',
      address: 'aws_s3_bucket_policy.access_logs',
      values: {
        bucket: 'aws_s3_bucket.access_logs',
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

    // Another bucket in the plan, but it does NOT reference access_logs as its log target.
    const appBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'app',
      address: 'aws_s3_bucket.app',
      values: {
        bucket: 'my-app-data',
      },
    } as unknown as TerraformResource;

    // A logging configuration exists in the plan, but it targets some OTHER bucket,
    // not access_logs - so access_logs is not exempted via reference form.
    const unrelatedLogging: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'unrelated',
      address: 'aws_s3_bucket_logging.unrelated',
      values: {
        bucket: 'aws_s3_bucket.app',
        target_bucket: 'aws_s3_bucket.some_other_log_bucket',
      },
    } as unknown as TerraformResource;

    const allResources = [accessLogsBucket, accessLogsBucketPolicy, appBucket, unrelatedLogging];

    const factory = new S3001TfAdapterFactory();
    expect(factory.appliesTo(accessLogsBucket.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: accessLogsBucket,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('S3-001');
    expect(result!.resourceName).toBe('aws_s3_bucket.access_logs');
    expect(result!.resourceType).toBe('aws_s3_bucket');
    expect(result!.status).toBe('Open');
    expect(result!.issue).toMatch(/logging/i);
  });
});
