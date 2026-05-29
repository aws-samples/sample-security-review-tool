import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (CloudFormation):
 * An S3 bucket has no logging configuration but appears intended as a log destination
 * (e.g., by name or by a bucket policy granting the S3 logging service principal write
 * access), without any other bucket in the template explicitly referencing it as a target.
 *
 * Expected: FLAG. Naming heuristics and policy hints are NOT sufficient evidence to
 * exempt a bucket from the server access logging requirement. Only an explicit
 * reference from another bucket's LoggingConfiguration.DestinationBucketName grants
 * the exemption.
 */
describe('S3-001 [CFN] REQ-05: bucket appears intended as log destination by name/policy only -> flag', () => {
  it('flags a bucket whose name suggests "logs" but no other bucket references it as a log target', () => {
    const template: Template = {
      Resources: {
        // This bucket "looks like" a log destination by naming convention,
        // and its policy grants the S3 logging service principal write access,
        // but no other bucket in the template explicitly targets it.
        AccessLogsBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-app-access-logs',
          },
        },
        AccessLogsBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'AccessLogsBucket',
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
        // Another bucket exists but does NOT reference AccessLogsBucket as its log target.
        AppBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-app-data',
            // No LoggingConfiguration -> does not reference AccessLogsBucket.
          },
        },
      },
    } as unknown as Template;

    const factory = new S3001CfnAdapterFactory();
    const resource = template.Resources!['AccessLogsBucket']!;
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'AccessLogsBucket',
    };

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('S3-001');
    expect(result!.resourceName).toBe('AccessLogsBucket');
    expect(result!.resourceType).toBe('AWS::S3::Bucket');
    expect(result!.status).toBe('Open');
    expect(result!.issue).toMatch(/logging/i);
  });
});
