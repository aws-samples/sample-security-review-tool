import { describe, it, expect } from 'vitest';
import { Neptune002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/neptune/002-auto-minor-version-upgrade.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Neptune002Rule', () => {
  const rule = new Neptune002Rule();
  const stackName = 'test-stack';

  // Helper function to create Neptune DBInstance test resources
  function createNeptuneInstanceResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::Neptune::DBInstance',
      Properties: {
        DBClusterIdentifier: 'test-neptune-cluster',
        DBInstanceClass: 'db.r5.large',
        ...props
      },
      LogicalId: props.LogicalId || 'TestNeptuneInstance'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('NEPTUNE-002');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to Neptune DBInstance resources', () => {
      expect(rule.appliesTo('AWS::Neptune::DBInstance')).toBe(true);
      expect(rule.appliesTo('AWS::Neptune::DBCluster')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Auto Minor Version Upgrade Tests', () => {
    it('should pass when AutoMinorVersionUpgrade is true', () => {
      // Arrange
      const resource = createNeptuneInstanceResource({
        AutoMinorVersionUpgrade: true
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should fail when AutoMinorVersionUpgrade is false', () => {
      // Arrange
      const resource = createNeptuneInstanceResource({
        AutoMinorVersionUpgrade: false
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBInstance');
      expect(result?.resourceName).toBe('TestNeptuneInstance');
      expect(result?.issue).toContain('Neptune DB instance does not have auto minor version upgrades enabled');
      expect(result?.fix).toContain('Set AutoMinorVersionUpgrade to true');
    });

    it('should fail when AutoMinorVersionUpgrade is missing', () => {
      // Arrange
      const resource = createNeptuneInstanceResource();

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBInstance');
      expect(result?.resourceName).toBe('TestNeptuneInstance');
      expect(result?.issue).toContain('Neptune DB instance does not have auto minor version upgrades enabled');
      expect(result?.fix).toContain('Add AutoMinorVersionUpgrade: true');
    });

    it('should handle CloudFormation intrinsic functions', () => {
      // Arrange
      const resource = createNeptuneInstanceResource({
        AutoMinorVersionUpgrade: { Ref: 'EnableAutoMinorVersionUpgrade' }
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
        Type: 'AWS::Neptune::DBInstance',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBInstance');
      expect(result?.resourceName).toBe('MissingProperties');
      expect(result?.issue).toContain('Neptune DB instance does not have auto minor version upgrades enabled');
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
