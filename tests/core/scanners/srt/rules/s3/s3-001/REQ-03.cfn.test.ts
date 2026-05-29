import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-03 (CFN): self-logging bucket passes', () => {
  it('passes when bucket has LoggingConfiguration pointing to itself', () => {
    const template: Template = {
      Resources: {
        SelfLoggingBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'self-logging-bucket',
            LoggingConfiguration: {
              // !Ref SelfLoggingBucket would resolve to the logical id "SelfLoggingBucket".
              DestinationBucketName: 'SelfLoggingBucket',
              LogFilePrefix: 'logs/',
            },
          },
        },
      },
    };

    const factory = new S3001CfnAdapterFactory();
    const resource = template.Resources!['SelfLoggingBucket'];
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'SelfLoggingBucket',
    };

    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
