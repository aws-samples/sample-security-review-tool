import { describe, it, expect } from 'vitest';
import { S3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 CloudFormation - REQ-01: bucket without logging and not a log destination', () => {
  it('flags an S3 bucket that has no logging configuration and is not referenced as a log destination by any other bucket', () => {
    const template: Template = {
      Resources: {
        UnloggedBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'unlogged-bucket',
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.UnloggedBucket,
      logicalId: 'UnloggedBucket',
    };

    const factory = new S3001CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);

    const adapter = factory.bind(context);
    const control = new S3001Control();
    const result = control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('S3-001');
    expect(result!.resourceName).toBe('UnloggedBucket');
    expect(result!.resourceType).toBe('AWS::S3::Bucket');
    expect(result!.status).toBe('Open');
    expect(result!.priority).toBe('HIGH');
  });
});
