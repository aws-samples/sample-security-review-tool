import { describe, it, expect } from 'vitest';
import { DocumentDB002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/documentdb/002-log-exports.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('DocumentDB002Rule', () => {
  const rule = new DocumentDB002Rule();
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
      expect(rule.id).toBe('DOCDB-002');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to DocumentDB cluster resources', () => {
      expect(rule.appliesTo('AWS::DocDB::DBCluster')).toBe(true);
      expect(rule.appliesTo('AWS::RDS::DBCluster')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('DocumentDB Cluster Tests', () => {
    it('should flag cluster with missing EnableCloudwatchLogsExports property', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource();
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::DocDB::DBCluster');
      expect(result?.resourceName).toBe('TestDocumentDBCluster');
      expect(result?.issue).toContain('DocumentDB cluster does not have Log Exports feature enabled');
      expect(result?.fix).toContain('Add EnableCloudwatchLogsExports property with \'audit\'');
    });

    it('should flag cluster with non-array EnableCloudwatchLogsExports', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        EnableCloudwatchLogsExports: 'audit'
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DocumentDB cluster does not have Log Exports feature enabled');
      expect(result?.fix).toContain('Set EnableCloudwatchLogsExports to an array');
    });

    it('should flag cluster with empty EnableCloudwatchLogsExports array', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        EnableCloudwatchLogsExports: []
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DocumentDB cluster does not have Log Exports feature enabled');
      expect(result?.fix).toContain('Add \'audit\' to the EnableCloudwatchLogsExports array');
    });

    it('should flag cluster with EnableCloudwatchLogsExports array not containing audit logs', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        EnableCloudwatchLogsExports: ['profiler']
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DocumentDB cluster does not have Log Exports feature enabled');
      expect(result?.fix).toContain('Add \'audit\' to EnableCloudwatchLogsExports array');
    });

    it('should not flag cluster with EnableCloudwatchLogsExports array containing audit logs', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        EnableCloudwatchLogsExports: ['audit']
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag cluster with EnableCloudwatchLogsExports array containing audit logs (case insensitive)', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        EnableCloudwatchLogsExports: ['Audit']
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag cluster with EnableCloudwatchLogsExports array containing multiple log types including audit', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        EnableCloudwatchLogsExports: ['profiler', 'audit']
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).toBeNull();
    });
    
    it('should fail with EnableCloudwatchLogsExports array containing CloudFormation intrinsic function', () => {
      // Arrange
      const cluster = createDocumentDBClusterResource({
        EnableCloudwatchLogsExports: { Ref: 'LogTypeParameter' }
      });
      
      // Act
      const result = rule.evaluate(cluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Set EnableCloudwatchLogsExports to an explicit array containing \'audit\' rather than using CloudFormation functions that cannot be validated at scan time');
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
      expect(result?.issue).toContain('DocumentDB cluster does not have Log Exports feature enabled');
      expect(result?.fix).toContain('Configure EnableCloudwatchLogsExports with \'audit\'');
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
