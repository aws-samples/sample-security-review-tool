import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 CloudFormation — wildcard Principal Allow with NotPrincipal exclusion of a specific identity', () => {
  it('flags an Allow statement that has Principal:"*" and a NotPrincipal excluding one identity, with no Condition', () => {
    const template: Template = {
      Resources: {
        MyBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'MyBucket',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Sid: 'WildcardAllowExceptOneIdentity',
                  Effect: 'Allow',
                  Principal: '*',
                  NotPrincipal: {
                    AWS: 'arn:aws:iam::123456789012:role/TrustedRole',
                  },
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                },
              ],
            },
          },
        },
      },
    };

    const factory = new S3002CfnAdapterFactory();
    const resource = template.Resources!['MyBucketPolicy']!;
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyBucketPolicy',
    };
    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('S3-002');
    expect(result!.resourceType).toBe('AWS::S3::BucketPolicy');
    expect(result!.resourceName).toBe('MyBucketPolicy');
    expect(result!.status).toBe('Open');
  });
});
