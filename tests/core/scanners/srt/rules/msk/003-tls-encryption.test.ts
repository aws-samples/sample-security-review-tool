import { describe, it, expect } from 'vitest';
import MSK003Rule from '../../../../../../src/assess/scanning/security-matrix/rules/msk/003-tls-encryption.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('MSK003Rule - TLS Encryption Between Brokers', () => {
  const rule = MSK003Rule;

  it('should pass when no EncryptionInfo is specified (default TLS enabled)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClusterName: 'test-cluster'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when EncryptionInfo is empty (default TLS enabled)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        EncryptionInfo: {}
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when EncryptionInTransit is not specified (default TLS enabled)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        EncryptionInfo: {
          EncryptionAtRest: {
            DataVolumeKMSKeyId: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when InCluster is explicitly set to true', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        EncryptionInfo: {
          EncryptionInTransit: {
            InCluster: true
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when InCluster is explicitly set to false', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        EncryptionInfo: {
          EncryptionInTransit: {
            InCluster: false
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.issue).toContain('MSK cluster is not configured with TLS encryption between brokers');
    expect(result?.fix).toContain('Remove EncryptionInfo.EncryptionInTransit.InCluster: false or set it to true');
  });

  it('should pass with complex EncryptionInTransit configuration with InCluster true', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        EncryptionInfo: {
          EncryptionInTransit: {
            InCluster: true,
            ClientBroker: 'TLS'
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when InCluster is not specified but other EncryptionInTransit properties are set', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        EncryptionInfo: {
          EncryptionInTransit: {
            ClientBroker: 'TLS'
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should ignore non-MSK resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestS3Bucket',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});