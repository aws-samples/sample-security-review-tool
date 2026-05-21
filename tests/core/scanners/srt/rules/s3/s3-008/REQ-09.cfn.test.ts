import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 CloudFormation - REQ-09: Lifecycle on a different bucket does not cover the assessed bucket', () => {
  it('flags the assessed bucket when a sibling bucket has a lifecycle configuration but the assessed bucket does not', () => {
    const template: Template = {
      Resources: {
        BucketWithLifecycle: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'bucket-with-lifecycle',
            LifecycleConfiguration: {
              Rules: [
                {
                  Id: 'ExpireOldObjects',
                  Status: 'Enabled',
                  ExpirationInDays: 365,
                },
              ],
            },
          },
        },
        AssessedBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'assessed-bucket',
            // No LifecycleConfiguration on this bucket
          },
        },
      },
    };

    const logicalId = 'AssessedBucket';
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources![logicalId],
      logicalId,
    };

    const factory = new S3008CfnAdapterFactory();
    expect(factory.appliesTo(context.resource.Type)).toBe(true);

    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('S3-008');
    expect(result!.resourceName).toBe('AssessedBucket');
    expect(result!.resourceType).toBe('AWS::S3::Bucket');
    expect(result!.status).toBe('Open');
    expect(result!.priority).toBe('HIGH');
  });
});
