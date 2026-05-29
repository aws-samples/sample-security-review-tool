import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-08 (CFN): empty LoggingConfiguration block should be flagged', () => {
  it('flags an S3 bucket whose LoggingConfiguration is an empty object (no DestinationBucketName)', () => {
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-bucket',
            // Logging configuration block is present but empty — no destination bucket.
            // Per the rule's rationale this does not actually enable log delivery.
            LoggingConfiguration: {},
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

    const factory = new S3001CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-001');
    expect(result?.resourceName).toBe('MyBucket');
    expect(result?.resourceType).toBe('AWS::S3::Bucket');
    expect(result?.status).toBe('Open');
  });
});
