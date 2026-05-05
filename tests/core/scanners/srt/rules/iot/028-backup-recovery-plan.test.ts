import { describe, it, expect } from 'vitest';
import iot028Rule from '../../../../../../src/assess/scanning/security-matrix/rules/iot/028-backup-recovery-plan.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoT028Rule - Define backup and recovery plan', () => {
  const rule = iot028Rule;
  const stackName = 'test-stack';

  describe('Basic Rule Properties', () => {
    it('should have correct rule properties', () => {
      expect(rule.id).toBe('IOT-028');
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to correct resource types', () => {
      expect(rule.appliesTo('AWS::IoT::Thing')).toBe(true);
      expect(rule.appliesTo('AWS::IoTSiteWise::Gateway')).toBe(true);
      expect(rule.appliesTo('AWS::IoTAnalytics::Datastore')).toBe(true);
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
    });
  });

  describe('Backup Mechanism Evaluation', () => {
    it('should pass when S3 backup is configured', () => {
      const thing = {
        Type: 'AWS::IoT::Thing',
        LogicalId: 'TestThing',
        Properties: { ThingName: 'test-thing' }
      };
      const s3Bucket = {
        Type: 'AWS::S3::Bucket',
        LogicalId: 'BackupBucket',
        Properties: {
          VersioningConfiguration: { Status: 'Enabled' }
        }
      };

      const result = rule.evaluate(thing, stackName, [thing, s3Bucket]);
      expect(result).toBeNull();
    });

    it('should pass when DynamoDB backup is configured', () => {
      const thing = {
        Type: 'AWS::IoT::Thing',
        LogicalId: 'TestThing',
        Properties: { ThingName: 'test-thing' }
      };
      const dynamoTable = {
        Type: 'AWS::DynamoDB::Table',
        LogicalId: 'DataTable',
        Properties: {
          BackupPolicy: { PointInTimeRecoveryEnabled: true }
        }
      };

      const result = rule.evaluate(thing, stackName, [thing, dynamoTable]);
      expect(result).toBeNull();
    });

    it('should pass when backup topic rule exists', () => {
      const thing = {
        Type: 'AWS::IoT::Thing',
        LogicalId: 'TestThing',
        Properties: { ThingName: 'test-thing' }
      };
      const topicRule = {
        Type: 'AWS::IoT::TopicRule',
        LogicalId: 'BackupRule',
        Properties: {
          TopicRulePayload: {
            Actions: [{ s3: { BucketName: 'backup-bucket' } }]
          }
        }
      };

      const result = rule.evaluate(thing, stackName, [thing, topicRule]);
      expect(result).toBeNull();
    });
  });

  describe('Recovery Mechanism Evaluation', () => {
    it('should pass when recovery Lambda exists', () => {
      const thing = {
        Type: 'AWS::IoT::Thing',
        LogicalId: 'TestThing',
        Properties: { ThingName: 'test-thing' }
      };
      const recoveryLambda = {
        Type: 'AWS::Lambda::Function',
        LogicalId: 'RecoveryFunction',
        Properties: {
          FunctionName: 'device-recovery-handler'
        }
      };

      const result = rule.evaluate(thing, stackName, [thing, recoveryLambda]);
      expect(result).toBeNull();
    });

    it('should pass when CloudWatch alarms with actions exist', () => {
      const thing = {
        Type: 'AWS::IoT::Thing',
        LogicalId: 'TestThing',
        Properties: { ThingName: 'test-thing' }
      };
      const alarm = {
        Type: 'AWS::CloudWatch::Alarm',
        LogicalId: 'DeviceAlarm',
        Properties: {
          AlarmActions: ['arn:aws:sns:us-east-1:123456789012:recovery-topic']
        }
      };

      const result = rule.evaluate(thing, stackName, [thing, alarm]);
      expect(result).toBeNull();
    });
  });

  describe('Resiliency Features Evaluation', () => {
    it('should pass when Device Defender is configured', () => {
      const thing = {
        Type: 'AWS::IoT::Thing',
        LogicalId: 'TestThing',
        Properties: { ThingName: 'test-thing' }
      };
      const securityProfile = {
        Type: 'AWS::IoT::SecurityProfile',
        LogicalId: 'DeviceProfile',
        Properties: { SecurityProfileName: 'device-security' }
      };

      const result = rule.evaluate(thing, stackName, [thing, securityProfile]);
      expect(result).toBeNull();
    });

    it('should pass when multiple AZs are configured', () => {
      const thing = {
        Type: 'AWS::IoT::Thing',
        LogicalId: 'TestThing',
        Properties: { ThingName: 'test-thing' }
      };
      const subnet1 = {
        Type: 'AWS::EC2::Subnet',
        LogicalId: 'Subnet1',
        Properties: { AvailabilityZone: 'us-east-1a' }
      };
      const subnet2 = {
        Type: 'AWS::EC2::Subnet',
        LogicalId: 'Subnet2',
        Properties: { AvailabilityZone: 'us-east-1b' }
      };

      const result = rule.evaluate(thing, stackName, [thing, subnet1, subnet2]);
      expect(result).toBeNull();
    });

    it('should pass when multiple SiteWise gateways exist', () => {
      const gateway1 = {
        Type: 'AWS::IoTSiteWise::Gateway',
        LogicalId: 'Gateway1',
        Properties: { GatewayName: 'gateway-1' }
      };
      const gateway2 = {
        Type: 'AWS::IoTSiteWise::Gateway',
        LogicalId: 'Gateway2',
        Properties: { GatewayName: 'gateway-2' }
      };

      const result = rule.evaluate(gateway1, stackName, [gateway1, gateway2]);
      expect(result).toBeNull();
    });
  });

  describe('IoT Analytics Datastore Evaluation', () => {
    it('should pass when datastore has retention policy', () => {
      const datastore = {
        Type: 'AWS::IoTAnalytics::Datastore',
        LogicalId: 'TestDatastore',
        Properties: {
          DatastoreName: 'test-datastore',
          RetentionPeriod: { NumberOfDays: 30 }
        }
      };

      const result = rule.evaluate(datastore, stackName, [datastore]);
      expect(result).toBeNull();
    });

    it('should pass when datastore uses service-managed S3', () => {
      const datastore = {
        Type: 'AWS::IoTAnalytics::Datastore',
        LogicalId: 'TestDatastore',
        Properties: {
          DatastoreName: 'test-datastore',
          DatastoreStorage: { ServiceManagedS3: {} }
        }
      };

      const result = rule.evaluate(datastore, stackName, [datastore]);
      expect(result).toBeNull();
    });
  });

  describe('Failure Cases', () => {
    it('should fail when no backup, recovery, or resiliency mechanisms exist', () => {
      const thing = {
        Type: 'AWS::IoT::Thing',
        LogicalId: 'TestThing',
        Properties: { ThingName: 'test-thing' }
      };

      const result = rule.evaluate(thing, stackName, [thing]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('no backup, recovery, or resiliency mechanisms');
    });
  });

  describe('Edge Cases', () => {
    it('should ignore non-applicable resources', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        LogicalId: 'TestBucket',
        Properties: { BucketName: 'my-bucket' }
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle missing Properties', () => {
      const resource = {
        Type: 'AWS::IoT::Thing',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});