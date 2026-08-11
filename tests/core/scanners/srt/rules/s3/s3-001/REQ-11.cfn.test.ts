import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-11 (S3-001) — CloudFormation
 *
 * REQ-07 passes a conditional logging configuration because the outcome is unknowable.
 * That reasoning only holds while some branch could enable logging. When no branch names
 * a destination bucket, logging is off whichever way the condition resolves, so the
 * exemption does not apply and the bucket is flagged.
 */
describe('S3-001 [CFN] — REQ-11: conditional logging where no branch delivers logs', () => {
  const factory = new S3001CfnAdapterFactory();

  const evaluate = (loggingConfiguration: unknown) => {
    const template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'my-bucket', LoggingConfiguration: loggingConfiguration },
        },
      },
    } as unknown as Template;

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['MyBucket'],
      logicalId: 'MyBucket',
    };

    return s3001Control.run(factory.bind(context), context);
  };

  it('flags when both branches resolve to AWS::NoValue', () => {
    const result = evaluate({
      'Fn::If': ['EnableLogging', { Ref: 'AWS::NoValue' }, { Ref: 'AWS::NoValue' }],
    });

    expect(result?.check_id).toBe('S3-001');
  });

  it('flags when branches set only a LogFilePrefix and never a destination', () => {
    const result = evaluate({
      'Fn::If': ['EnableLogging', { LogFilePrefix: 'logs/' }, { LogFilePrefix: 'archive/' }],
    });

    expect(result?.check_id).toBe('S3-001');
  });

  it('flags when both branches are empty objects', () => {
    expect(evaluate({ 'Fn::If': ['EnableLogging', {}, {}] })?.check_id).toBe('S3-001');
  });

  it('flags when a nested condition still delivers logs nowhere', () => {
    const result = evaluate({
      'Fn::If': [
        'OuterCondition',
        { 'Fn::If': ['InnerCondition', { Ref: 'AWS::NoValue' }, { LogFilePrefix: 'logs/' }] },
        { Ref: 'AWS::NoValue' },
      ],
    });

    expect(result?.check_id).toBe('S3-001');
  });

  it('still passes when one branch delivers logs to a destination (REQ-07)', () => {
    const result = evaluate({
      'Fn::If': ['EnableLogging', { DestinationBucketName: 'central-logs' }, { Ref: 'AWS::NoValue' }],
    });

    expect(result).toBeNull();
  });

  it('still passes when a nested branch delivers logs to a destination', () => {
    const result = evaluate({
      'Fn::If': [
        'OuterCondition',
        { 'Fn::If': ['InnerCondition', { DestinationBucketName: 'central-logs' }, { Ref: 'AWS::NoValue' }] },
        { Ref: 'AWS::NoValue' },
      ],
    });

    expect(result).toBeNull();
  });
});
