import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 CloudFormation - REQ-01: bucket without logging and not a log destination', () => {
  it('flags an S3 bucket that has no LoggingConfiguration and is not referenced as a log destination by any other bucket', () => {
    const template: Template = {
      Resources: {
        UnloggedBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-unlogged-bucket',
          },
        },
        // Another bucket also without logging - and it does NOT point at UnloggedBucket
        OtherBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'some-other-bucket',
          },
        },
      },
    };

    const factory = new S3001CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.UnloggedBucket,
      logicalId: 'UnloggedBucket',
    };

    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-001');
    expect(result?.resourceName).toBe('UnloggedBucket');
    expect(result?.resourceType).toBe('AWS::S3::Bucket');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });
});
