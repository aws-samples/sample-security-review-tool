import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 REQ-07 CloudFormation: lifecycle configuration depends on an unresolvable condition', () => {
  it('passes (no finding) when LifecycleConfiguration is an unresolved Fn::If intrinsic', () => {
    // Per preprocessing rules, Fn::If is NOT resolved and remains an opaque object.
    // The rule must not be able to conclusively determine non-compliance, so it must pass.
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LifecycleConfiguration: {
              'Fn::If': [
                'EnableLifecycle',
                {
                  Rules: [
                    {
                      Id: 'ExpireOldObjects',
                      Status: 'Enabled',
                      ExpirationInDays: 30,
                    },
                  ],
                },
                { Ref: 'AWS::NoValue' },
              ],
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['MyBucket'],
      logicalId: 'MyBucket',
    };

    const factory = new S3008CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes (no finding) when a lifecycle Rule entry itself is wrapped in Fn::If', () => {
    // The Rules array contains an unresolved Fn::If. Whether the rule is enabled
    // cannot be determined, so the rule must not flag this as non-compliant.
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LifecycleConfiguration: {
              Rules: [
                {
                  'Fn::If': [
                    'EnableRule',
                    {
                      Id: 'ExpireOldObjects',
                      Status: 'Enabled',
                      ExpirationInDays: 30,
                    },
                    { Ref: 'AWS::NoValue' },
                  ],
                },
              ],
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['MyBucket'],
      logicalId: 'MyBucket',
    };

    const factory = new S3008CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
