import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(template: Template, logicalId: string): CfnContext {
  const resource = template.Resources![logicalId];
  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
}

describe('S3-002 CloudFormation - allow statement without principal', () => {
  it('passes when an Allow statement omits the Principal element (invalid IAM grant, no principal receives access)', () => {
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
                  Effect: 'Allow',
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                  // Principal intentionally omitted
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const context = buildContext(template, 'MyBucketPolicy');
    const factory = new S3002CfnAdapterFactory();
    const adapter = factory.bind(context);

    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
