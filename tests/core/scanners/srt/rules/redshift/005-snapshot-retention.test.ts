import { describe, it, expect } from 'vitest';
import { Redshift005Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/redshift/005-snapshot-retention.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Redshift005Rule', () => {
  const rule = new Redshift005Rule();
  const stackName = 'test-stack';

  // Helper function to create RedShift Cluster test resources
  function createClusterResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::Redshift::Cluster',
      Properties: {
        ClusterType: 'single-node',
        NodeType: 'dc2.large',
        MasterUsername: 'admin',
        MasterUserPassword: 'Password123',
        ...props
      },
      LogicalId: props.LogicalId || 'TestCluster'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('REDSHIFT-005');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to RedShift Cluster resources', () => {
      expect(rule.appliesTo('AWS::Redshift::Cluster')).toBe(true);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Valid Configuration Tests', () => {
    it('should pass with valid retention period (7 days)', () => {
      // Arrange
      const resource = createClusterResource({
        AutomatedSnapshotRetentionPeriod: 7
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass with minimum valid retention period (1 day)', () => {
      // Arrange
      const resource = createClusterResource({
        AutomatedSnapshotRetentionPeriod: 1
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass with maximum valid retention period (35 days)', () => {
      // Arrange
      const resource = createClusterResource({
        AutomatedSnapshotRetentionPeriod: 35
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass with string representation of valid number', () => {
      // Arrange
      const resource = createClusterResource({
        AutomatedSnapshotRetentionPeriod: '7'
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Invalid Configuration Tests', () => {
    it('should fail when retention is disabled (0 days)', () => {
      // Arrange
      const resource = createClusterResource({
        AutomatedSnapshotRetentionPeriod: 0
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have automated snapshot retention configured');
      expect(result?.fix).toContain('Enable automated snapshots by setting AutomatedSnapshotRetentionPeriod to a value between 1 and 35 days');
    });

    it('should fail when retention period is negative', () => {
      // Arrange
      const resource = createClusterResource({
        AutomatedSnapshotRetentionPeriod: -5
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have automated snapshot retention configured');
      expect(result?.fix).toContain('Set AutomatedSnapshotRetentionPeriod to a value between 1 and 35 days');
    });

    it('should fail when retention period exceeds maximum (> 35 days)', () => {
      // Arrange
      const resource = createClusterResource({
        AutomatedSnapshotRetentionPeriod: 40
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have automated snapshot retention configured');
      expect(result?.fix).toContain('Set AutomatedSnapshotRetentionPeriod to a value between 1 and 35 days');
    });

    it('should fail with non-numeric value', () => {
      // Arrange
      const resource = createClusterResource({
        AutomatedSnapshotRetentionPeriod: 'invalid'
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have automated snapshot retention configured');
      expect(result?.fix).toContain('Set AutomatedSnapshotRetentionPeriod to a valid numeric value between 1 and 35 days');
    });

    it('should fail when AutomatedSnapshotRetentionPeriod is missing', () => {
      // Arrange
      const resource = createClusterResource();

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have automated snapshot retention configured');
      expect(result?.fix).toContain('Explicitly set AutomatedSnapshotRetentionPeriod to a value between 1 and 35 days (recommended: 7 days or more for production workloads)');
    });

    it('should fail when AutomatedSnapshotRetentionPeriod is intrinsic function', () => {
      // Arrange
      const resource = createClusterResource({
        AutomatedSnapshotRetentionPeriod: {}
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have automated snapshot retention configured');
      expect(result?.fix).toContain('Set AutomatedSnapshotRetentionPeriod to an explicit numeric value between 1 and 35 days rather than using CloudFormation functions that cannot be validated at scan time');
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Arrange
      const resource = {
        Type: 'AWS::Redshift::Cluster',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('MissingProperties');
      expect(result?.issue).toContain('Redshift cluster does not have automated snapshot retention configured');
      expect(result?.fix).toContain('Configure AutomatedSnapshotRetentionPeriod to a value between 1 and 35 days');
    });

    it('should fail when using CloudFormation intrinsic function', () => {
      // Arrange
      const resource = createClusterResource({
        AutomatedSnapshotRetentionPeriod: { Ref: 'RetentionPeriodParameter' }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
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
