import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 CloudFormation - REQ-08: lifecycle rule status unresolved', () => {
  it('passes when the only lifecycle rule has an unresolved Status (Fn::If) - cannot conclusively determine no enabled rule exists', () => {
    const template: Template = {
      Conditions: {
        EnableLifecycle: { 'Fn::Equals': [{ Ref: 'AWS::Region' }, 'us-east-1'] },
      },
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LifecycleConfiguration: {
              Rules: [
                {
                  Id: 'expire-old-objects',
                  ExpirationInDays: 30,
                  Status: {
                    'Fn::If': ['EnableLifecycle', 'Enabled', 'Disabled'],
                  },
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyBucket,
      logicalId: 'MyBucket',
    };

    const factory = new S3008CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
