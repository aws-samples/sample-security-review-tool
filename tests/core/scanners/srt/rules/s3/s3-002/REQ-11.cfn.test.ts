import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 CloudFormation - REQ-11: multiple allow statements with one wildcard principal and others named', () => {
  it('flags when a bucket policy has multiple Allow statements and at least one uses an unconstrained wildcard principal', () => {
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        MyBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: { Ref: 'MyBucket' },
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  // Well-scoped statement naming a specific principal
                  Effect: 'Allow',
                  Principal: { AWS: 'arn:aws:iam::111111111111:role/TrustedRole' },
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                },
                {
                  // Unconstrained wildcard principal - this should cause a flag
                  Effect: 'Allow',
                  Principal: '*',
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                },
                {
                  // Another well-scoped statement naming a specific principal
                  Effect: 'Allow',
                  Principal: { AWS: 'arn:aws:iam::222222222222:role/AnotherTrustedRole' },
                  Action: 's3:PutObject',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                },
              ],
            },
          },
        },
      },
    };

    const factory = new S3002CfnAdapterFactory();
    const policyResource = template.Resources!['MyBucketPolicy'];
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: policyResource,
      logicalId: 'MyBucketPolicy',
    };

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('S3-002');
    expect(result!.resourceName).toBe('MyBucketPolicy');
    expect(result!.resourceType).toBe('AWS::S3::BucketPolicy');
    expect(result!.issue).toMatch(/wildcard principal/i);
  });
});
