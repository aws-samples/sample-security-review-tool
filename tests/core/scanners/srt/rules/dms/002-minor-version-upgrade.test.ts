import { describe, it, expect } from 'vitest';
import { DMS003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/dms/003-minor-version-upgrade.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('DMS003Rule', () => {
  const rule = new DMS003Rule();
  const stackName = 'test-stack';

  // Helper function to create DMS replication instance test resources
  function createDMSReplicationInstanceResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::DMS::ReplicationInstance',
      Properties: {
        ReplicationInstanceClass: 'dms.t3.medium',
        ...props
      },
      LogicalId: props.LogicalId || 'TestDMSReplicationInstance'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('DMS-003');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to DMS replication instance resources', () => {
      expect(rule.appliesTo('AWS::DMS::ReplicationInstance')).toBe(true);
      expect(rule.appliesTo('AWS::RDS::DBInstance')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('DMS Replication Instance Tests', () => {
    it('should flag instance with missing AutoMinorVersionUpgrade property', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource();
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::DMS::ReplicationInstance');
      expect(result?.resourceName).toBe('TestDMSReplicationInstance');
      expect(result?.issue).toContain('DMS replication instance does not have auto minor version upgrade enabled');
      expect(result?.fix).toContain('Add AutoMinorVersionUpgrade property and set it to true');
    });

    it('should flag instance with AutoMinorVersionUpgrade set to false', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource({
        AutoMinorVersionUpgrade: false
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DMS replication instance does not have auto minor version upgrade enabled');
      expect(result?.fix).toContain('Set AutoMinorVersionUpgrade property to true');
    });

    it('should flag instance with AutoMinorVersionUpgrade set to string "false"', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource({
        AutoMinorVersionUpgrade: 'false'
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DMS replication instance does not have auto minor version upgrade enabled');
      expect(result?.fix).toContain('Set AutoMinorVersionUpgrade property to true');
    });

    it('should not flag instance with AutoMinorVersionUpgrade set to true', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource({
        AutoMinorVersionUpgrade: true
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag instance with AutoMinorVersionUpgrade set to string "true"', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource({
        AutoMinorVersionUpgrade: 'true'
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should flag instance with AutoMinorVersionUpgrade as CloudFormation intrinsic function', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource({
        AutoMinorVersionUpgrade: { Ref: 'AutoMinorVersionUpgradeParameter' }
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DMS replication instance does not have auto minor version upgrade enabled');
      expect(result?.fix).toContain('Set AutoMinorVersionUpgrade property to an explicit boolean value (true) rather than using CloudFormation functions');
    });

    it('should flag instance with AutoMinorVersionUpgrade set to unexpected value', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource({
        AutoMinorVersionUpgrade: 'invalid'
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DMS replication instance does not have auto minor version upgrade enabled');
      expect(result?.fix).toContain('Set AutoMinorVersionUpgrade property to true');
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Arrange
      const instance = {
        Type: 'AWS::DMS::ReplicationInstance',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DMS replication instance does not have auto minor version upgrade enabled');
      expect(result?.fix).toContain('Configure AutoMinorVersionUpgrade property to true');
    });

    it('should ignore non-applicable resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };
      
      // Act
      const result = rule.evaluate(resource, stackName);
      
      // Assert
      expect(result).toBeNull();
    });
  });
});
