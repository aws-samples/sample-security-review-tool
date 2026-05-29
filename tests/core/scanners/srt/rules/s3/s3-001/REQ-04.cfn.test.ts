import { describe, it, expect } from 'vitest';
import { S3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-04 CFN: bucket referenced as log destination is exempt', () => {
  it('passes when bucket has no logging but is referenced as DestinationBucketName by another bucket', () => {
    const template: Template = {
      Resources: {
        LogDestinationBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        AppBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              // After preprocessing, !Ref LogDestinationBucket -> "LogDestinationBucket"
              DestinationBucketName: 'LogDestinationBucket',
              LogFilePrefix: 'app-logs/',
            },
          },
        },
      },
    } as unknown as Template;

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['LogDestinationBucket']!,
      logicalId: 'LogDestinationBucket',
    };

    const factory = new S3001CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);

    const adapter = factory.bind(context);
    const control = new S3001Control();
    const result = control.run(adapter, context);

    expect(result).toBeNull();
  });
});
