import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (CFN): Bucket policy Allow statement whose principal ARN cannot be
 * resolved to a determinable account (e.g. a parameterized/dynamic ARN) must
 * NOT be flagged. The rule should silently pass unresolvable principals to
 * avoid false positives.
 *
 * After preprocessing, `!Ref UntrustedRoleArn` (a Parameter without a Default)
 * resolves to the literal string "DEFAULT" — a dynamic value the analyzer
 * cannot attribute to any particular account. It is neither the wildcard `*`
 * nor a Service principal, so the control's two flagging paths do not apply.
 */
describe('S3-002 CFN — unresolvable principal ARN (pass)', () => {
  it('does not flag an Allow statement whose AWS principal ARN is a parameterized/unresolvable value', () => {
    const template: Template = {
      Parameters: {
        // No Default → preprocessing resolves !Ref UntrustedRoleArn to "DEFAULT"
        UntrustedRoleArn: { Type: 'String' },
      },
      Resources: {
        BucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'my-bucket',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  // Simulates the post-preprocessing view of `!Ref UntrustedRoleArn`
                  Principal: { AWS: 'DEFAULT' },
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                },
              ],
            },
          },
        },
      },
    };

    const resource = template.Resources!['BucketPolicy']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'BucketPolicy',
    };

    const factory = new S3002CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::BucketPolicy')).toBe(true);
    const adapter = factory.bind(context);

    const result = s3002Control.run(adapter, context);
    expect(result).toBeNull();
  });

  it('does not flag an Allow statement whose AWS principal is an unresolved intrinsic object', () => {
    // An Fn::If (or Fn::ImportValue) survives preprocessing as an object — the
    // analyzer cannot determine the account attribution. It's not `*` and not
    // a Service principal, so it must pass.
    const template: Template = {
      Resources: {
        BucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'my-bucket',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: {
                      'Fn::If': [
                        'UseExternalPrincipal',
                        'arn:aws:iam::111111111111:role/ExternalRole',
                        'arn:aws:iam::222222222222:role/OtherRole',
                      ],
                    },
                  },
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                },
              ],
            },
          },
        },
      },
    };

    const resource = template.Resources!['BucketPolicy']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'BucketPolicy',
    };

    const adapter = new S3002CfnAdapterFactory().bind(context);
    const result = s3002Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
