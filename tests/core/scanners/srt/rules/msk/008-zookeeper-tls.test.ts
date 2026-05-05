import { describe, it, expect } from 'vitest';
import MSK008Rule from '../../../../../../src/assess/scanning/security-matrix/rules/msk/008-zookeeper-tls.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('MSK008Rule - ZooKeeper TLS Documentation', () => {
  const rule = MSK008Rule;

  it('should pass for Kafka versions before 2.5.1', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        KafkaVersion: '2.4.1'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass for Kafka 2.5.1+ with TLS configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        KafkaVersion: '2.6.0',
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

  it('should fail for Kafka 2.5.1+ without TLS configuration', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        KafkaVersion: '2.6.0'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.issue).toContain('requires documented TLS configuration for ZooKeeper nodes');
  });

  it('should fail for Kafka 2.5.1+ with non-TLS ClientBroker', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        KafkaVersion: '2.8.1',
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
  });

  it('should handle version 2.5.1 exactly', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        KafkaVersion: '2.5.1'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
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