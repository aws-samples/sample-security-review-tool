import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 CloudFormation - REQ-10: bucket referenced as log destination by multiple buckets', () => {
  it('passes when an S3 bucket has no logging config but is the log destination for multiple other buckets', () => {
    const template: Template = {
      Resources: {
        CentralLogsBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        AppBucketOne: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              DestinationBucketName: 'CentralLogsBucket',
            },
          },
        },
        AppBucketTwo: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              DestinationBucketName: 'CentralLogsBucket',
            },
          },
        },
        AppBucketThree: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              DestinationBucketName: 'CentralLogsBucket',
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new S3001CfnAdapterFactory();
    const logicalId = 'CentralLogsBucket';
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
