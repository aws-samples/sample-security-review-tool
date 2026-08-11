import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 CloudFormation - wildcard principal with unresolvable Effect', () => {
  it('passes when the statement Effect is unresolvable (e.g., Fn::If) even if principal is a wildcard', () => {
    // Fn::If is NOT resolved by parseCfnTemplate — it remains as an opaque object.
    // The rule's isAllow check requires effect to be a string equal to "allow",
    // so an object-shaped effect cannot be asserted as Allow → the rule should pass.
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
                  Effect: {
                    'Fn::If': ['UseAllowEffect', 'Allow', 'Deny'],
                  },
                  Principal: '*',
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
    expect(factory.appliesTo('AWS::S3::BucketPolicy')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
