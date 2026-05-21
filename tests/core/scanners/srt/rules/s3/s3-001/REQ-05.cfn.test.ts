import { describe, it, expect } from 'vitest';
import { S3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-05 (CloudFormation): bucket appears intended as a log destination but no other bucket references it', () => {
  it('flags a bucket whose name and policy suggest it is a log destination, when no other bucket explicitly targets it', () => {
    const template: Template = {
      Resources: {
        // This bucket has a "log destination"-ish name and a bucket policy granting
        // the S3 logging service principal write access. These are heuristic hints
        // of intent but are NOT sufficient evidence per the rule's rationale.
        AccessLogsBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-app-access-logs',
          },
        },
        AccessLogsBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: { Ref: 'AccessLogsBucket' },
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: { Service: 'logging.s3.amazonaws.com' },
                  Action: 's3:PutObject',
                  Resource: 'arn:aws:s3:::my-app-access-logs/*',
                },
              ],
            },
          },
        },
        // An unrelated bucket exists in the template, but it does NOT reference
        // AccessLogsBucket as its DestinationBucketName.
        UnrelatedBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'unrelated-bucket',
          },
        },
      },
    } as unknown as Template;

    const factory = new S3001CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.AccessLogsBucket,
      logicalId: 'AccessLogsBucket',
    };

    const adapter = factory.bind(context);
    const control = new S3001Control();
    const result = control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-001');
    expect(result?.resourceName).toBe('AccessLogsBucket');
    expect(result?.resourceType).toBe('AWS::S3::Bucket');
    expect(result?.status).toBe('Open');
  });
});
