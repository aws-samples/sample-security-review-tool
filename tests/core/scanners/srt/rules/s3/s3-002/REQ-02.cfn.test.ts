import { describe, it, expect } from 'vitest';
import { Template } from 'cloudform-types';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 REQ-02 (CloudFormation): Bucket policy with only deny statements should pass', () => {
  it('does not flag a bucket policy that contains only Deny statements', () => {
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-bucket',
          },
        },
        MyBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'MyBucket',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Sid: 'DenyInsecureTransport',
                  Effect: 'Deny',
                  Principal: '*',
                  Action: 's3:*',
                  Resource: [
                    'arn:aws:s3:::my-bucket',
                    'arn:aws:s3:::my-bucket/*',
                  ],
                  Condition: {
                    Bool: { 'aws:SecureTransport': 'false' },
                  },
                },
                {
                  Sid: 'DenyUnencryptedObjectUploads',
                  Effect: 'Deny',
                  Principal: '*',
                  Action: 's3:PutObject',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                  Condition: {
                    StringNotEquals: {
                      's3:x-amz-server-side-encryption': 'AES256',
                    },
                  },
                },
                {
                  Sid: 'DenySpecificPrincipal',
                  Effect: 'Deny',
                  Principal: { AWS: 'arn:aws:iam::999999999999:root' },
                  Action: 's3:*',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                },
              ],
            },
          },
        },
      },
    };

    const factory = new S3002CfnAdapterFactory();
    const policyResource = template.Resources!['MyBucketPolicy']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: policyResource,
      logicalId: 'MyBucketPolicy',
    };

    expect(factory.appliesTo('AWS::S3::BucketPolicy')).toBe(true);
    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
