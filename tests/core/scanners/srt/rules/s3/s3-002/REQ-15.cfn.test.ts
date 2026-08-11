import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 REQ-15 (CloudFormation): principal list mixing wildcard and specific principals without condition', () => {
  it('flags a bucket policy where the Allow statement Principal is a list containing "*" and specific principals with no condition', () => {
    const logicalId = 'MixedPrincipalBucketPolicy';
    const resource = {
      Type: 'AWS::S3::BucketPolicy',
      Properties: {
        Bucket: 'MyBucket',
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                AWS: [
                  '*',
                  'arn:aws:iam::123456789012:role/TrustedRole',
                  'arn:aws:iam::123456789012:user/TrustedUser',
                ],
              },
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::my-bucket/*',
            },
          ],
        },
      },
    } as unknown as NonNullable<Template['Resources']>[string];

    const template: Template = {
      Resources: {
        [logicalId]: resource,
      },
    } as unknown as Template;

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new S3002CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::BucketPolicy')).toBe(true);
    const adapter = factory.bind(context);

    const result = s3002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-002');
    expect(result?.resourceName).toBe(logicalId);
    expect(result?.resourceType).toBe('AWS::S3::BucketPolicy');
    expect(result?.issue).toMatch(/wildcard principal/i);
  });
});
