import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new S3002CfnAdapterFactory();

function buildContext(template: Template, logicalId: string): CfnContext {
  const resource = template.Resources![logicalId];
  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
}

describe('S3-002 REQ-03 (CFN): wildcard principal in Allow statement with no conditions', () => {
  it('flags a bucket policy whose Allow statement uses Principal: "*" with no Condition', () => {
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        MyBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'MyBucket',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: '*',
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::MyBucket/*',
                },
              ],
            },
          },
        },
      },
    };

    const context = buildContext(template, 'MyBucketPolicy');
    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-002');
    expect(result?.resourceType).toBe('AWS::S3::BucketPolicy');
    expect(result?.resourceName).toBe('MyBucketPolicy');
  });

  it('flags a bucket policy whose Allow statement uses Principal: { AWS: "*" } with no Condition', () => {
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        MyBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'MyBucket',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: { AWS: '*' },
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::MyBucket/*',
                },
              ],
            },
          },
        },
      },
    };

    const context = buildContext(template, 'MyBucketPolicy');
    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-002');
  });
});
