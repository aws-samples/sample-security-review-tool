import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

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

describe('S3-002 CloudFormation - REQ-06: account-scoped principal grants', () => {
  it('passes when Allow statement grants access to an AWS account ID', () => {
    const ctx = buildContext({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '123456789012' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    });

    const adapter = new S3002CfnAdapterFactory().bind(ctx);
    const result = s3002Control.run(adapter, ctx);

    expect(result).toBeNull();
  });

  it('passes when Allow statement grants access via an account root ARN', () => {
    const ctx = buildContext({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::123456789012:root' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    });

    const adapter = new S3002CfnAdapterFactory().bind(ctx);
    const result = s3002Control.run(adapter, ctx);

    expect(result).toBeNull();
  });

  it('passes when Allow statement grants access to a list of account root ARNs', () => {
    const ctx = buildContext({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: [
              'arn:aws:iam::123456789012:root',
              'arn:aws:iam::210987654321:root',
            ],
          },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    });

    const adapter = new S3002CfnAdapterFactory().bind(ctx);
    const result = s3002Control.run(adapter, ctx);

    expect(result).toBeNull();
  });
});
