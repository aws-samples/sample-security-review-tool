import { describe, it, expect } from 'vitest';
import { Neptune003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/neptune/003-backup-retention-period.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Neptune003Rule', () => {
  const rule = new Neptune003Rule();
  const stackName = 'test-stack';

  // Helper function to create Neptune DBCluster test resources
  function createNeptuneClusterResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::Neptune::DBCluster',
      Properties: {
        DBClusterIdentifier: 'test-neptune-cluster',
        ...props
      },
      LogicalId: props.LogicalId || 'TestNeptuneCluster'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('NEPTUNE-003');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to Neptune DBCluster resources', () => {
      expect(rule.appliesTo('AWS::Neptune::DBCluster')).toBe(true);
      expect(rule.appliesTo('AWS::Neptune::DBInstance')).toBe(false);
      expect(rule.appliesTo('AWS::RDS::DBCluster')).toBe(false);
    });
  });

  describe('Backup Retention Period Tests', () => {
    it('should pass when BackupRetentionPeriod is 7 days', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        BackupRetentionPeriod: 7
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when BackupRetentionPeriod is greater than 7 days', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        BackupRetentionPeriod: 14
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should fail when BackupRetentionPeriod is less than 7 days', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        BackupRetentionPeriod: 3
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune cluster does not have a minimum backup retention period of 7 days configured');
      expect(result?.fix).toContain('Increase BackupRetentionPeriod to at least 7 days');
    });

    it('should fail when BackupRetentionPeriod is missing', () => {
      // Arrange
      const resource = createNeptuneClusterResource();

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune cluster does not have a minimum backup retention period of 7 days configured');
      expect(result?.fix).toContain('Set BackupRetentionPeriod to at least 7 days');
    });

    it('should handle CloudFormation intrinsic functions', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        BackupRetentionPeriod: { Ref: 'BackupRetentionPeriodParam' }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Arrange
      const resource = {
        Type: 'AWS::Neptune::DBCluster',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('MissingProperties');
      expect(result?.issue).toContain('Neptune cluster does not have a minimum backup retention period of 7 days configured');
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

      // Act & Assert
      // First check that the rule doesn't apply to this resource type
      expect(rule.appliesTo(resource.Type)).toBe(false);
      
      // Then check that evaluate returns null for non-applicable resources
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});
