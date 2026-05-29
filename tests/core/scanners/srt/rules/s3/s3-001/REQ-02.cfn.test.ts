import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-02 (CloudFormation): bucket with logging configured to a separate destination bucket', () => {
  it('passes when LoggingConfiguration delivers logs to a distinct destination bucket', () => {
    const template: Template = {
      Resources: {
        SourceBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              DestinationBucketName: 'LogsBucket',
              LogFilePrefix: 'access-logs/',
            },
          },
        },
        LogsBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
      },
    };

    const factory = new S3001CfnAdapterFactory();
    const sourceResource = template.Resources!['SourceBucket']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: sourceResource,
      logicalId: 'SourceBucket',
    };

    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
