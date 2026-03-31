import { describe, it, expect } from 'vitest';
import MSK002Rule from '../../../../../../src/assess/scanning/security-matrix/rules/msk/002-client-broker-encryption.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('MSK002Rule - Client-Broker Encryption', () => {
  const rule = MSK002Rule;

  it('should pass when no EncryptionInfo is specified (default TLS)', () => {
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

  it('should pass when ClientBroker is TLS', () => {
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

  it('should fail when ClientBroker is PLAINTEXT', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        EncryptionInfo: {
          EncryptionInTransit: {
            ClientBroker: 'PLAINTEXT'
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.issue).toContain('allows plaintext communication between clients and brokers');
    expect(result?.fix).toContain("Set EncryptionInfo.EncryptionInTransit.ClientBroker to 'TLS'");
  });

  it('should fail when ClientBroker is TLS_PLAINTEXT', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        EncryptionInfo: {
          EncryptionInTransit: {
            ClientBroker: 'TLS_PLAINTEXT'
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.issue).toContain('allows plaintext communication between clients and brokers');
  });

  it('should pass when ClientBroker is not specified but EncryptionInTransit exists', () => {
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