import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 REQ-05 (CFN): S3 bucket with lifecycle configuration but empty rules collection', () => {
  it('flags an S3 bucket whose LifecycleConfiguration has an empty Rules array', () => {
    const template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LifecycleConfiguration: {
              Rules: [],
            },
          },
        },
      },
    } as any;

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources.MyBucket,
      logicalId: 'MyBucket',
    };

    const factory = new S3008CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-008');
    expect(result?.resourceType).toBe('AWS::S3::Bucket');
    expect(result?.resourceName).toBe('MyBucket');
    expect(result?.status).toBe('Open');
  });
});
