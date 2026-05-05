import { describe, it, expect } from 'vitest';
import MSK006Rule from '../../../../../../src/assess/scanning/security-matrix/rules/msk/006-broker-log-delivery.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('MSK006Rule - Broker Log Delivery', () => {
  const rule = MSK006Rule;

  it('should pass when CloudWatch Logs is enabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        LoggingInfo: {
          BrokerLogs: {
            CloudWatchLogs: {
              Enabled: true,
              LogGroup: 'msk-broker-logs'
            }
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when S3 logging is enabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        LoggingInfo: {
          BrokerLogs: {
            S3: {
              Enabled: true,
              Bucket: 'msk-logs-bucket'
            }
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when Firehose logging is enabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        LoggingInfo: {
          BrokerLogs: {
            Firehose: {
              Enabled: true,
              DeliveryStream: 'msk-logs-stream'
            }
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when multiple log destinations are enabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        LoggingInfo: {
          BrokerLogs: {
            CloudWatchLogs: {
              Enabled: true,
              LogGroup: 'msk-broker-logs'
            },
            S3: {
              Enabled: true,
              Bucket: 'msk-logs-bucket'
            }
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when LoggingInfo is missing', () => {
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
    expect(result?.issue).toContain('MSK cluster does not have broker log delivery configured');
    expect(result?.fix).toContain('Add LoggingInfo.BrokerLogs.CloudWatchLogs with Enabled: true and LogGroup');
  });

  it('should fail when BrokerLogs is missing', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        LoggingInfo: {}
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.fix).toContain('Add LoggingInfo.BrokerLogs.CloudWatchLogs with Enabled: true and LogGroup');
  });

  it('should fail when all log destinations are disabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        LoggingInfo: {
          BrokerLogs: {
            CloudWatchLogs: {
              Enabled: false
            },
            S3: {
              Enabled: false
            },
            Firehose: {
              Enabled: false
            }
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.fix).toContain('Set LoggingInfo.BrokerLogs.CloudWatchLogs.Enabled to true and LogGroup');
  });

  it('should fail when log destinations are not explicitly enabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        LoggingInfo: {
          BrokerLogs: {
            CloudWatchLogs: {
              LogGroup: 'msk-broker-logs'
            }
          }
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