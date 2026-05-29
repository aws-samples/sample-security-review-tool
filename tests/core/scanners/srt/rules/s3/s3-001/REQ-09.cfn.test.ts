import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 / REQ-09 (CloudFormation): logging configured with destination bucket and log file prefix', () => {
  it('passes when LoggingConfiguration includes DestinationBucketName and LogFilePrefix', () => {
    const template: Template = {
      Resources: {
        LogsBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-logs-bucket',
          },
        },
        AppBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-app-bucket',
            LoggingConfiguration: {
              DestinationBucketName: 'LogsBucket',
              LogFilePrefix: 'access-logs/',
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new S3001CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['AppBucket']!,
      logicalId: 'AppBucket',
    };

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
