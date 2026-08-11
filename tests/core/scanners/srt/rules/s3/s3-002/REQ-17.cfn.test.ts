import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 CFN — REQ-17: Allow statement grants access to an explicit canonical user identifier', () => {
  it('passes when the bucket policy allow statement lists a specific CanonicalUser principal', () => {
    const template = {
      Resources: {
        MyBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'MyBucket',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    CanonicalUser:
                      '79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be',
                  },
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const resource = template.Resources!['MyBucketPolicy']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyBucketPolicy',
    };

    const factory = new S3002CfnAdapterFactory();
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when a CanonicalUser principal is provided as an array of specific identifiers', () => {
    const template = {
      Resources: {
        MyBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'MyBucket',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    CanonicalUser: [
                      '79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be',
                      '8a6f5c1f4f9e3a2b1d0c9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c',
                    ],
                  },
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const resource = template.Resources!['MyBucketPolicy']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyBucketPolicy',
    };

    const factory = new S3002CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
