import { describe, expect, it } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(policyDocument: unknown): CfnContext {
  const resource = {
    Type: 'AWS::S3::BucketPolicy',
    Properties: {
      Bucket: 'MyBucket',
      PolicyDocument: policyDocument,
    },
  } as unknown as NonNullable<Template['Resources']>[string];

  const template = {
    Resources: {
      MyBucketPolicy: resource,
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'MyBucketPolicy',
  };
}

describe('S3-002 CFN — service principal with source-scope condition passes', () => {
  it('passes when a service principal grant is scoped by aws:SourceAccount', () => {
    const context = buildContext({
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

    const adapter = new S3002CfnAdapterFactory().bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when a service principal grant is scoped by aws:SourceArn', () => {
    const context = buildContext({
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

    const adapter = new S3002CfnAdapterFactory().bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
