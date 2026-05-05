import { describe, it, expect } from 'vitest';
import { Redshift004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/redshift/004-publicly-accessible.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Redshift004Rule', () => {
  const rule = new Redshift004Rule();
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
      expect(rule.id).toBe('REDSHIFT-004');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to RedShift Cluster resources', () => {
      expect(rule.appliesTo('AWS::Redshift::Cluster')).toBe(true);
      expect(rule.appliesTo('AWS::Redshift::ClusterParameterGroup')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Cluster Tests', () => {
    it('should fail when PubliclyAccessible is undefined', () => {
      // Arrange
      const resource = createClusterResource();

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster is publicly accessible');
      expect(result?.fix).toContain('Explicitly set PubliclyAccessible to false');
    });

    it('should fail when PubliclyAccessible is null', () => {
      // Arrange
      const resource = createClusterResource({
        PubliclyAccessible: null
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster is publicly accessible');
      expect(result?.fix).toContain('Explicitly set PubliclyAccessible to false');
    });

    it('should fail when PubliclyAccessible is true', () => {
      // Arrange
      const resource = createClusterResource({
        PubliclyAccessible: true
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster is publicly accessible');
      expect(result?.fix).toContain('Set PubliclyAccessible to false');
    });

    it('should fail when PubliclyAccessible is "true"', () => {
      // Arrange
      const resource = createClusterResource({
        PubliclyAccessible: 'true'
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster is publicly accessible');
      expect(result?.fix).toContain('Set PubliclyAccessible to false');
    });

    it('should pass when PubliclyAccessible is false', () => {
      // Arrange
      const resource = createClusterResource({
        PubliclyAccessible: false
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when PubliclyAccessible is "false"', () => {
      // Arrange
      const resource = createClusterResource({
        PubliclyAccessible: 'false'
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should fail when PubliclyAccessible uses CloudFormation intrinsic function', () => {
      // Arrange
      const resource = createClusterResource({
        PubliclyAccessible: { Ref: 'PubliclyAccessibleParameter' }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.fix).toContain('Set PubliclyAccessible to an explicit boolean value (false) rather than using CloudFormation functions that cannot be validated at scan time');
    });

    it('should fail when PubliclyAccessible has unexpected value', () => {
      // Arrange
      const resource = createClusterResource({
        PubliclyAccessible: 'not-a-boolean'
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster is publicly accessible');
      expect(result?.fix).toContain('Set PubliclyAccessible to false');
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
      expect(result?.issue).toContain('Redshift cluster is publicly accessible');
      expect(result?.fix).toContain('Configure PubliclyAccessible property to false');
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
