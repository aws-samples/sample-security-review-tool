import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new S3002TfAdapterFactory();

function buildContext(resource: TerraformResource, allResources: TerraformResource[]): TfContext {
  return {
    projectName: 'test-project',
    resource,
    allResources,
  };
}

describe('S3-002 REQ-03 (TF): wildcard principal in Allow statement with no conditions', () => {
  it('flags an aws_s3_bucket_policy whose Allow statement uses Principal "*" with no Condition (literal bucket name)', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    };

    const policyDoc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-site-bucket/*',
        },
      ],
    });

    const policy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'site',
      address: 'aws_s3_bucket_policy.site',
      values: {
        bucket: 'my-site-bucket',
        policy: policyDoc,
      },
    };

    const context = buildContext(policy, [bucket, policy]);
    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-002');
    expect(result?.resourceType).toBe('aws_s3_bucket_policy');
    expect(result?.resourceName).toBe('aws_s3_bucket_policy.site');
  });

  it('flags an aws_s3_bucket_policy whose Allow statement uses Principal { AWS: "*" } with no Condition (reference form)', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    };

    const policyDoc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-site-bucket/*',
        },
      ],
    });

    const policy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'site',
      address: 'aws_s3_bucket_policy.site',
      values: {
        // reference form — plan reader collapses aws_s3_bucket.site.id to the address string
        bucket: 'aws_s3_bucket.site',
        policy: policyDoc,
      },
    };

    const context = buildContext(policy, [bucket, policy]);
    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-002');
  });
});
