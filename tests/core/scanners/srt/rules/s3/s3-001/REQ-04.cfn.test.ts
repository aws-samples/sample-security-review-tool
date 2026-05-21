import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-04 (CloudFormation): bucket referenced as a log destination by another bucket is exempt', () => {
  it('returns no finding for a bucket without logging that is referenced as DestinationBucketName by another bucket', () => {
    // The "LogDestinationBucket" has no LoggingConfiguration of its own.
    // The "AppBucket" references it via LoggingConfiguration.DestinationBucketName: !Ref LogDestinationBucket,
    // which after preprocessing becomes the literal string "LogDestinationBucket".
    const template: Template = {
      Resources: {
        LogDestinationBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-log-destination-bucket',
          },
        },
        AppBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-app-bucket',
            LoggingConfiguration: {
              DestinationBucketName: 'LogDestinationBucket',
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new S3001CfnAdapterFactory();
    const logicalId = 'LogDestinationBucket';
    const resource = template.Resources![logicalId];

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
