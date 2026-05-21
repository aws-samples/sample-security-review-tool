import { describe, it, expect } from 'vitest';
import { S3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 REQ-03 (CloudFormation): Bucket has lifecycle config but every rule is explicitly disabled', () => {
  it('flags an S3 bucket whose lifecycle configuration contains only disabled rules', () => {
    const template: Template = {
      Resources: {
        DisabledLifecycleBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'disabled-lifecycle-bucket',
            LifecycleConfiguration: {
              Rules: [
                {
                  Id: 'expire-old-objects',
                  Status: 'Disabled',
                  ExpirationInDays: 30,
                },
                {
                  Id: 'transition-to-glacier',
                  Status: 'Disabled',
                  Transitions: [
                    {
                      StorageClass: 'GLACIER',
                      TransitionInDays: 90,
                    },
                  ],
                },
              ],
            },
          },
        },
      },
    };

    const logicalId = 'DisabledLifecycleBucket';
    const resource = template.Resources![logicalId];

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new S3008CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);

    const adapter = factory.bind(context);
    const control = new S3008Control();
    const result = control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-008');
    expect(result?.resourceName).toBe(logicalId);
    expect(result?.resourceType).toBe('AWS::S3::Bucket');
    expect(result?.status).toBe('Open');
  });
});
