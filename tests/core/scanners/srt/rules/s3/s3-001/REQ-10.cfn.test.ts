import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 CloudFormation - REQ-10: bucket referenced as log destination by multiple other buckets', () => {
  it('passes when the bucket has no logging configuration but is the log destination for multiple other buckets', () => {
    const template: Template = {
      Resources: {
        CentralLogBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        AppBucketOne: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              DestinationBucketName: 'CentralLogBucket',
            },
          },
        },
        AppBucketTwo: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              DestinationBucketName: 'CentralLogBucket',
            },
          },
        },
        AppBucketThree: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              DestinationBucketName: 'CentralLogBucket',
            },
          },
        },
      },
    } as unknown as Template;

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.CentralLogBucket,
      logicalId: 'CentralLogBucket',
    };

    const factory = new S3001CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
