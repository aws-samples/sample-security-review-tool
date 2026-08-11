import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (Terraform): Bucket policy Allow statement grants access to an AWS
 * service principal with NO condition restricting the source account or
 * source ARN. Per the resolved decision, unrestricted service-principal
 * grants constitute an untrusted grant and MUST be flagged.
 */
describe('S3-002 REQ-07 (Terraform): unrestricted service principal grant', () => {
  const factory = new S3002TfAdapterFactory();

  function buildContext(policyDocument: unknown, bucketRef = 'aws_s3_bucket.site'): TfContext {
    const policyString = typeof policyDocument === 'string' ? policyDocument : JSON.stringify(policyDocument);
    const bucketPolicy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'site',
      address: 'aws_s3_bucket_policy.site',
      values: {
        bucket: bucketRef,
        policy: policyString,
      },
    } as unknown as TerraformResource;
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    } as unknown as TerraformResource;
    return {
      projectName: 'test-project',
      resource: bucketPolicy,
      allResources: [bucketPolicy, bucket],
    };
  }

  it('flags an Allow statement to an AWS service principal with no Condition (reference form for bucket)', () => {
    const context = buildContext({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: 'logging.s3.amazonaws.com' },
          Action: 's3:PutObject',
          Resource: 'arn:aws:s3:::my-site-bucket/*',
        },
      ],
    });

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-002');
    expect(result?.resourceType).toBe('aws_s3_bucket_policy');
    expect(result?.resourceName).toBe('aws_s3_bucket_policy.site');
  });

  it('flags an Allow statement to a service principal array with no Condition', () => {
    const context = buildContext({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: ['cloudtrail.amazonaws.com', 'config.amazonaws.com'] },
          Action: 's3:PutObject',
          Resource: 'arn:aws:s3:::my-site-bucket/*',
        },
      ],
    });

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-002');
  });

  it('does NOT flag when a service-principal Allow statement is scoped by aws:SourceAccount', () => {
    const context = buildContext({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: 'logging.s3.amazonaws.com' },
          Action: 's3:PutObject',
          Resource: 'arn:aws:s3:::my-site-bucket/*',
          Condition: {
            StringEquals: { 'aws:SourceAccount': '123456789012' },
          },
        },
      ],
    });

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does NOT flag when a service-principal Allow statement is scoped by aws:SourceArn', () => {
    const context = buildContext({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: 'logging.s3.amazonaws.com' },
          Action: 's3:PutObject',
          Resource: 'arn:aws:s3:::my-site-bucket/*',
          Condition: {
            ArnLike: {
              'aws:SourceArn': 'arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail',
            },
          },
        },
      ],
    });

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
