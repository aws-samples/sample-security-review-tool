import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 REQ-02 (CloudFormation): S3 bucket with at least one enabled lifecycle rule passes', () => {
  it('returns null (pass) when the bucket has a LifecycleConfiguration with an enabled rule', () => {
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-app-bucket',
            LifecycleConfiguration: {
              Rules: [
                {
                  Id: 'expire-old-objects',
                  Status: 'Enabled',
                  ExpirationInDays: 365,
                },
              ],
            },
          },
        },
      },
    };

    const logicalId = 'MyBucket';
    const resource = template.Resources![logicalId];

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new S3008CfnAdapterFactory();
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('returns null (pass) when the bucket has multiple rules including at least one enabled', () => {
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LifecycleConfiguration: {
              Rules: [
                {
                  Id: 'disabled-rule',
                  Status: 'Disabled',
                  ExpirationInDays: 30,
                },
                {
                  Id: 'enabled-rule',
                  Status: 'Enabled',
                  ExpirationInDays: 90,
                },
              ],
            },
          },
        },
      },
    };

    const logicalId = 'MyBucket';
    const resource = template.Resources![logicalId];

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new S3008CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
