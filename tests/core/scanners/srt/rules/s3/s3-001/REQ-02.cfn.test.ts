import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-02 CloudFormation: S3 bucket with server access logging to a separate destination bucket', () => {
  it('should pass when bucket has LoggingConfiguration with a separate DestinationBucketName', () => {
    const template = {
      Resources: {
        AppBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              DestinationBucketName: 'LogDestinationBucket',
              LogFilePrefix: 'app-logs/',
            },
          },
        },
        LogDestinationBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template: template as never,
      resource: template.Resources.AppBucket as never,
      logicalId: 'AppBucket',
    };

    const factory = new S3001CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
