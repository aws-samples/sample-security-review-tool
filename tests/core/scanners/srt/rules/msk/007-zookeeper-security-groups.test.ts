import { describe, it, expect } from 'vitest';
import MSK007Rule from '../../../../../../src/assess/scanning/security-matrix/rules/msk/007-zookeeper-security-groups.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('MSK007Rule - ZooKeeper Security Groups', () => {
  const rule = MSK007Rule;

  it('should pass when security groups are configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        BrokerNodeGroupInfo: {
          SecurityGroups: ['sg-12345678']
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when multiple security groups are configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        BrokerNodeGroupInfo: {
          SecurityGroups: ['sg-12345678', 'sg-87654321']
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when BrokerNodeGroupInfo is missing', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClusterName: 'test-cluster'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.issue).toContain('MSK cluster does not have security groups configured to limit ZooKeeper access');
    expect(result?.fix).toContain('Configure BrokerNodeGroupInfo with SecurityGroups');
  });

  it('should fail when SecurityGroups is missing', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        BrokerNodeGroupInfo: {
          InstanceType: 'kafka.m5.large'
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.fix).toContain('Configure SecurityGroups in BrokerNodeGroupInfo');
  });

  it('should fail when SecurityGroups is empty array', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        BrokerNodeGroupInfo: {
          SecurityGroups: []
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
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