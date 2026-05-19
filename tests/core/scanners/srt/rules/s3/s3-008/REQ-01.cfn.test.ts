import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { CfnS3AdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.cfn.adapter.js';
import type { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008: S3 buckets must implement a lifecycle policy', () => {
  describe('Scenario: S3 bucket has no LifecycleConfiguration property at all', () => {
    it('should flag an S3 bucket without LifecycleConfiguration as non-compliant', () => {
      const resource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-test-bucket',
        },
      } as any;

      const context: CfnContext = {
        stackName: 'TestStack',
        template: {
          Resources: {
            MyBucket: resource,
          },
        } as any,
        resource,
        logicalId: 'MyBucket',
      };

      const factory = new CfnS3AdapterFactory();
      const adapter = factory.bind(context);

      const result = s3008Control.run(adapter, context);

      expect(result).not.toBeNull();
      expect(result?.check_id).toBe('S3-008');
      expect(result?.resourceType).toBe('AWS::S3::Bucket');
      expect(result?.resourceName).toBe('MyBucket');
      expect(result?.status).toBe('Open');
      expect(result?.priority).toBe('HIGH');
      expect(result?.path).toBe('TestStack');
      expect(result?.source).toBe('security-matrix');
    });
  });
});
