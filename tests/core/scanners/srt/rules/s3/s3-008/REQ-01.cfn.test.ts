import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 REQ-01 (CloudFormation): S3 bucket has no lifecycle configuration defined', () => {
  it('flags an S3 bucket that has no LifecycleConfiguration property at all', () => {
    const template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-bucket-without-lifecycle',
          },
        },
      },
    };

    const logicalId = 'MyBucket';
    const resource = template.Resources[logicalId];

    const context: CfnContext = {
      stackName: 'test-stack',
      template: template as any,
      resource: resource as any,
      logicalId,
    };

    const factory = new S3008CfnAdapterFactory();
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-008');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
    expect(result?.resourceType).toBe('AWS::S3::Bucket');
    expect(result?.resourceName).toBe('MyBucket');
  });
});
