import { describe, it, expect } from 'vitest';
import { Redshift002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/redshift/002-default-master-username.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Redshift002Rule', () => {
  const rule = new Redshift002Rule();
  const stackName = 'test-stack';

  // Helper function to create RedShift Cluster test resources
  function createClusterResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::Redshift::Cluster',
      Properties: {
        ClusterType: 'single-node',
        NodeType: 'dc2.large',
        MasterUserPassword: 'Password123',
        ...props
      },
      LogicalId: props.LogicalId || 'TestCluster'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('REDSHIFT-002');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to RedShift Cluster resources only', () => {
      expect(rule.appliesTo('AWS::Redshift::Cluster')).toBe(true);
      expect(rule.appliesTo('AWS::Redshift::ClusterParameterGroup')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Master Username Tests', () => {
    it('should pass when MasterUsername is a custom value', () => {
      // Arrange
      const resource = createClusterResource({
        MasterUsername: 'custom_admin'
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should fail when MasterUsername is "awsuser"', () => {
      // Arrange
      const resource = createClusterResource({
        MasterUsername: 'awsuser'
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster is using the default master username "awsuser"');
      expect(result?.fix).toContain('Change the MasterUsername to a value other than "awsuser"');
    });

    it('should fail when MasterUsername is missing', () => {
      // Arrange
      const resource = createClusterResource();

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster is using the default master username "awsuser"');
      expect(result?.fix).toContain('Specify a custom MasterUsername other than "awsuser"');
    });

    it('should pass when MasterUsername uses CloudFormation intrinsic function', () => {
      // Arrange
      const resource = createClusterResource({
        MasterUsername: { Ref: 'MasterUsernameParameter' }
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
        Type: 'AWS::Redshift::Cluster',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('MissingProperties');
      expect(result?.issue).toContain('Redshift cluster is using the default master username "awsuser"');
      expect(result?.fix).toContain('Specify a custom MasterUsername other than "awsuser"');
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
