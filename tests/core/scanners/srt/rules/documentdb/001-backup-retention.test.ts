import { describe, it, expect } from 'vitest';
import { DocumentDB001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/documentdb/001-backup-retention.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('DocumentDB001Rule', () => {
  const rule = new DocumentDB001Rule();
  const stackName = 'test-stack';

  // Helper function to create DocumentDB cluster test resources
  function createDocumentDBClusterResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::DocDB::DBCluster',
      Properties: {
        MasterUsername: 'admin',
        MasterUserPassword: 'password',
        ...props
      },
      LogicalId: props.LogicalId || 'TestDocumentDBCluster'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('DOCDB-001');
    });

    it('should have MEDIUM priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to DocumentDB cluster resources', () => {
      expect(rule.appliesTo('AWS::DocDB::DBCluster')).toBe(true);
      expect(rule.appliesTo('AWS::RDS::DBCluster')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('DocumentDB Cluster Tests', () => {
    it('should not flag cluster with undefined BackupRetentionPeriod (defaults to 1 day)', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource();
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should flag cluster with BackupRetentionPeriod set to 0', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        BackupRetentionPeriod: 0
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::DocDB::DBCluster');
      expect(result?.resourceName).toBe('TestDocumentDBCluster');
      expect(result?.issue).toContain('DocumentDB cluster does not have a minimum backup retention period configured');
      expect(result?.fix).toContain('Enable automated backups');
    });

    it('should flag cluster with BackupRetentionPeriod less than 1', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        BackupRetentionPeriod: -1
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DocumentDB cluster does not have a minimum backup retention period configured');
      expect(result?.fix).toContain('Set BackupRetentionPeriod to a value between 1 and 35 days');
    });

    it('should flag cluster with BackupRetentionPeriod greater than 35', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        BackupRetentionPeriod: 36
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DocumentDB cluster does not have a minimum backup retention period configured');
      expect(result?.fix).toContain('Set BackupRetentionPeriod to a value between 1 and 35 days');
    });

    it('should not flag cluster with BackupRetentionPeriod within valid range', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        BackupRetentionPeriod: 7
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag cluster with BackupRetentionPeriod at minimum valid value', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        BackupRetentionPeriod: 1
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag cluster with BackupRetentionPeriod at maximum valid value', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        BackupRetentionPeriod: 35
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should flag cluster with BackupRetentionPeriod as CloudFormation intrinsic function', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        BackupRetentionPeriod: { Ref: 'BackupRetentionParameter' }
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Set BackupRetentionPeriod to an explicit numeric value between 1 and 35 days rather than using CloudFormation functions that cannot be validated at scan time');
    });

    it('should flag cluster with BackupRetentionPeriod as non-numeric value', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        BackupRetentionPeriod: 'invalid'
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DocumentDB cluster does not have a minimum backup retention period configured');
      expect(result?.fix).toContain('Set BackupRetentionPeriod to a valid numeric value');
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Arrange
      const cluster = {
        Type: 'AWS::DocDB::DBCluster',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DocumentDB cluster does not have a minimum backup retention period configured');
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
