import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (S3-001) — CloudFormation
 *
 * The log-destination exemption requires an explicit reference as a log target (REQ-05).
 * Searching the whole logging block for the logical ID let unrelated values — a
 * LogFilePrefix being the realistic case — exempt a bucket that receives no logs.
 */
describe('S3-001 [CFN] — REQ-12: logical ID mentioned outside DestinationBucketName', () => {
  const factory = new S3001CfnAdapterFactory();

  const evaluate = (appBucketLogging: unknown, logicalId = 'LogBucket') => {
    const template = {
      Resources: {
        LogBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'logs' } },
        AppBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'app', LoggingConfiguration: appBucketLogging },
        },
      },
    } as unknown as Template;

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources![logicalId],
      logicalId,
    };

    return s3001Control.run(factory.bind(context), context);
  };

  it('flags a bucket whose ID appears only as another bucket\'s LogFilePrefix', () => {
    const result = evaluate({
      'Fn::If': [
        'EnableLogging',
        { DestinationBucketName: 'SomewhereElse', LogFilePrefix: 'LogBucket' },
        { Ref: 'AWS::NoValue' },
      ],
    });

    expect(result?.check_id).toBe('S3-001');
  });

  it('flags a bucket whose ID appears only as an unconditional LogFilePrefix', () => {
    const result = evaluate({ DestinationBucketName: 'SomewhereElse', LogFilePrefix: 'LogBucket' });

    expect(result?.check_id).toBe('S3-001');
  });

  it('exempts the bucket that is the actual conditional destination', () => {
    const result = evaluate({
      'Fn::If': [
        'EnableLogging',
        { DestinationBucketName: 'LogBucket', LogFilePrefix: 'app/' },
        { Ref: 'AWS::NoValue' },
      ],
    });

    expect(result).toBeNull();
  });

  it('exempts a destination referenced by Ref inside a condition', () => {
    const result = evaluate({
      'Fn::If': ['EnableLogging', { DestinationBucketName: { Ref: 'LogBucket' } }, { Ref: 'AWS::NoValue' }],
    });

    expect(result).toBeNull();
  });
});
