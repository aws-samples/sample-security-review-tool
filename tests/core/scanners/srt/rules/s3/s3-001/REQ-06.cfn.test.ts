import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-06 (CloudFormation): destination exemption applies when referencing bucket logging is unresolvable', () => {
  it('passes (no finding) for a bucket with no logging that is referenced as a log destination by another bucket whose own logging configuration is unresolvable', () => {
    // DestinationLogBucket: no logging configuration of its own, but is referenced as log destination by AppBucket.
    // AppBucket: has a LoggingConfiguration controlled by an Fn::If — unresolvable at analysis time.
    // The DestinationBucketName inside that unresolvable LoggingConfiguration cannot be confirmed.
    // Per resolved decision: when the referencing bucket's logging cannot be confirmed, apply the destination
    // exemption to DestinationLogBucket (i.e., do not emit a finding) to avoid false positives.
    const template: Template = {
      Resources: {
        DestinationLogBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        AppBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            // Unresolved intrinsic — preprocessing leaves Fn::If intact. The actual LoggingConfiguration
            // (and therefore its DestinationBucketName) is unknowable statically.
            LoggingConfiguration: {
              'Fn::If': [
                'EnableLogging',
                { DestinationBucketName: 'DestinationLogBucket', LogFilePrefix: 'logs/' },
                { Ref: 'AWS::NoValue' },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new S3001CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.DestinationLogBucket,
      logicalId: 'DestinationLogBucket',
    };

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
