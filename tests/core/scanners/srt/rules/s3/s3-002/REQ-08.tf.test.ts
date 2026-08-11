import { describe, expect, it } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(policyJson: string): TfContext {
  const resource: TerraformResource = {
    type: 'aws_s3_bucket_policy',
    name: 'site',
    address: 'aws_s3_bucket_policy.site',
    values: {
      bucket: 'aws_s3_bucket.site',
      policy: policyJson,
    },
  } as unknown as TerraformResource;

  return {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
}

describe('S3-002 Terraform — service principal with source-scope condition passes', () => {
  it('passes when a service principal grant is scoped by aws:SourceAccount', () => {
    const policy = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: 'cloudtrail.amazonaws.com' },
          Action: 's3:PutObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringEquals: {
              'aws:SourceAccount': '123456789012',
            },
          },
        },
      ],
    });

    const context = buildContext(policy);
    const adapter = new S3002TfAdapterFactory().bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when a service principal grant is scoped by aws:SourceArn', () => {
    const policy = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: 'logs.amazonaws.com' },
          Action: 's3:PutObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            ArnLike: {
              'aws:SourceArn': 'arn:aws:logs:us-east-1:123456789012:log-group:/my/log/group:*',
            },
          },
        },
      ],
    });

    const context = buildContext(policy);
    const adapter = new S3002TfAdapterFactory().bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
