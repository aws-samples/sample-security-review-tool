import { describe, it, expect } from 'vitest';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import ATH001Rule from '../../../../../../src/assess/scanning/security-matrix/rules/athena/001-query-results-encryption.cf.js';
import { ScanResult } from '../../../../../../src/core/scanners/base-scanner';

describe('ATH-001: Athena query results encryption rule', () => {
  const stackName = 'test-stack';

  function createWorkGroup(props: any = {}): CloudFormationResource {
    return {
      Type: 'AWS::Athena::WorkGroup',
      LogicalId: 'TestWorkGroup',
      Properties: {
        Name: 'test-workgroup',
        ...props
      }
    };
  }

  it('passes when encryption is properly configured with SSE_S3', () => {
    const resource = createWorkGroup({
      WorkGroupConfiguration: {
        ResultConfiguration: {
          EncryptionConfiguration: {
            EncryptionOption: 'SSE_S3'
          }
        }
      }
    });

    const result = ATH001Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('passes when encryption is properly configured with SSE_KMS and KmsKey', () => {
    const resource = createWorkGroup({
      WorkGroupConfiguration: {
        ResultConfiguration: {
          EncryptionConfiguration: {
            EncryptionOption: 'SSE_KMS',
            KmsKey: 'arn:aws:kms:us-east-1:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef'
          }
        }
      }
    });

    const result = ATH001Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('fails when EncryptionConfiguration is missing', () => {
    const resource = createWorkGroup({
      WorkGroupConfiguration: {
        ResultConfiguration: {}
      }
    });

    const result = ATH001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('Athena workgroup does not have encryption enabled for query results');
    expect((result as ScanResult).fix).toContain('Add WorkGroupConfiguration.ResultConfiguration.EncryptionConfiguration');
  });

  it('fails when ResultConfiguration is missing', () => {
    const resource = createWorkGroup({
      WorkGroupConfiguration: {}
    });

    const result = ATH001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('Athena workgroup does not have encryption enabled for query results');
  });

  it('fails when EncryptionOption is missing', () => {
    const resource = createWorkGroup({
      WorkGroupConfiguration: {
        ResultConfiguration: {
          EncryptionConfiguration: {}
        }
      }
    });

    const result = ATH001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).fix).toContain('Set EncryptionOption to \'SSE_S3\', \'SSE_KMS\', or \'CSE_KMS\'');
  });

  it('fails when EncryptionOption has invalid value', () => {
    const resource = createWorkGroup({
      WorkGroupConfiguration: {
        ResultConfiguration: {
          EncryptionConfiguration: {
            EncryptionOption: 'INVALID_OPTION'
          }
        }
      }
    });

    const result = ATH001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).fix).toContain('Set EncryptionOption to \'SSE_S3\', \'SSE_KMS\', or \'CSE_KMS\'');
  });

  it('fails when using SSE_KMS without KmsKey', () => {
    const resource = createWorkGroup({
      WorkGroupConfiguration: {
        ResultConfiguration: {
          EncryptionConfiguration: {
            EncryptionOption: 'SSE_KMS'
          }
        }
      }
    });

    const result = ATH001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).fix).toContain('When using SSE_KMS, specify a KMS key ARN');
  });

  it('fails when using CSE_KMS without KmsKey', () => {
    const resource = createWorkGroup({
      WorkGroupConfiguration: {
        ResultConfiguration: {
          EncryptionConfiguration: {
            EncryptionOption: 'CSE_KMS'
          }
        }
      }
    });

    const result = ATH001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).fix).toContain('When using CSE_KMS, specify a KMS key ARN');
  });

  it('ignores non-Athena resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestBucket',
      Properties: {
        BucketName: 'test-bucket'
      }
    };

    const result = ATH001Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });
});