import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 CloudFormation - empty statements collection', () => {
  it('passes when the bucket policy has a Statement array that is empty', () => {
    const template: Template = {
      Resources: {
        MyBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'MyBucket',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [],
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyBucketPolicy,
      logicalId: 'MyBucketPolicy',
    };

    const factory = new S3002CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::BucketPolicy')).toBe(true);

    const adapter = factory.bind(context);
    expect(adapter.getPolicyStatements()).toEqual([]);

    const result = s3002Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
