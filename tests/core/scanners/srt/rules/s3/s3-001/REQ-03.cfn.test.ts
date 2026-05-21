import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-03 (CFN): self-logging bucket', () => {
  it('passes (no finding) when bucket logs to itself', () => {
    const template = {
      Resources: {
        SelfLoggingBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              // After preprocessing, !Ref SelfLoggingBucket resolves to "SelfLoggingBucket"
              DestinationBucketName: 'SelfLoggingBucket',
              LogFilePrefix: 'self-logs/',
            },
          },
        },
      },
    } as unknown as CfnContext['template'];

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.SelfLoggingBucket,
      logicalId: 'SelfLoggingBucket',
    };

    const factory = new S3001CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);
    const adapter = factory.bind(context);

    const result = s3001Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
