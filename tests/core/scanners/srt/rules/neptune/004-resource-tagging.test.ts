import { describe, it, expect } from 'vitest';
import { Neptune004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/neptune/004-resource-tagging.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Neptune004Rule', () => {
  const rule = new Neptune004Rule();
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
      expect(rule.id).toBe('NEPTUNE-004');
    });

    it('should have MEDIUM priority', () => {
      expect(rule.priority).toBe('MEDIUM');
    });

    it('should apply to Neptune DBCluster resources only', () => {
      expect(rule.appliesTo('AWS::Neptune::DBCluster')).toBe(true);
      expect(rule.appliesTo('AWS::Neptune::DBInstance')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Resource Tagging Tests', () => {
    it('should pass when cluster has tags', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        Tags: [
          { Key: 'Environment', Value: 'Production' },
          { Key: 'Owner', Value: 'DataTeam' }
        ]
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should fail when cluster has no tags property', () => {
      // Arrange
      const resource = createNeptuneClusterResource();

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune cluster is missing required tags');
    });

    it('should fail when cluster has empty tags array', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        Tags: []
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune cluster is missing required tags');
    });

    it('should fail when cluster has tags defined with CloudFormation intrinsic functions', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        Tags: { Ref: 'ResourceTags' }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune cluster is missing required tags');
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
      expect(result?.issue).toContain('Neptune cluster is missing required tags');
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
      expect(rule.appliesTo(resource.Type)).toBe(false);
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});
