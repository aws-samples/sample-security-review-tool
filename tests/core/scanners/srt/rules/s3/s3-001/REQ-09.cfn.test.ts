import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 CloudFormation - REQ-09: bucket with logging configuration including destination and prefix', () => {
  it('passes (returns null) when LoggingConfiguration includes both DestinationBucketName and LogFilePrefix', () => {
    const template = {
      Resources: {
        AppBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              DestinationBucketName: 'LogDestinationBucket',
              LogFilePrefix: 'access-logs/',
            },
          },
        },
        LogDestinationBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
      },
    } as any;

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources.AppBucket,
      logicalId: 'AppBucket',
    };

    const factory = new S3001CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
