import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-06 (CloudFormation): destination bucket whose referencer has unresolvable logging config', () => {
  it('passes for a bucket with no logging that is referenced as a destination by a bucket whose own logging config is unresolvable (Fn::If)', () => {
    // Bucket "DestinationBucket" has no logging of its own.
    // Bucket "AppBucket" references DestinationBucket as its DestinationBucketName,
    // but the LoggingConfiguration as a whole is gated by an Fn::If — i.e. whether
    // AppBucket actually logs is unresolvable at analysis time. Per the resolved
    // decision, the destination exemption should still apply to DestinationBucket
    // to avoid false positives.
    const template: Template = {
      Resources: {
        DestinationBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        AppBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              'Fn::If': [
                'EnableLogging',
                { DestinationBucketName: 'DestinationBucket' },
                { Ref: 'AWS::NoValue' },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new S3001CfnAdapterFactory();
    const resource = template.Resources!['DestinationBucket']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'DestinationBucket',
    };

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
