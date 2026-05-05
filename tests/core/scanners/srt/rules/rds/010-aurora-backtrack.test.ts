import { describe, it, expect } from 'vitest';
import { Rds010Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/rds/010-aurora-backtrack.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Rds010Rule', () => {
  const rule = new Rds010Rule();
  const stackName = 'test-stack';

  // Helper function to create RDS DBCluster test resources
  function createRdsClusterResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::RDS::DBCluster',
      Properties: {
        Engine: 'aurora-mysql',
        MasterUsername: 'admin',
        MasterUserPassword: 'password',
        ...props
      },
      LogicalId: props.LogicalId || 'TestRdsCluster'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('RDS-010');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply only to RDS cluster resources', () => {
      expect(rule.appliesTo('AWS::RDS::DBCluster')).toBe(true);
      expect(rule.appliesTo('AWS::RDS::DBInstance')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('RDS Cluster Tests', () => {
    it('should flag RDS cluster without BacktrackWindow property', () => {
      // Arrange
      const rdsCluster = createRdsClusterResource();
      
      // Act
      const result = rule.evaluate(rdsCluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBCluster');
      expect(result?.resourceName).toBe('TestRdsCluster');
      expect(result?.issue).toContain('RDS Aurora Cluster does not have Backtrack enabled');
      expect(result?.fix).toContain('Set BacktrackWindow to a value greater than 0');
    });

    it('should flag RDS cluster with BacktrackWindow set to 0', () => {
      // Arrange
      const rdsCluster = createRdsClusterResource({
        BacktrackWindow: 0
      });
      
      // Act
      const result = rule.evaluate(rdsCluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBCluster');
      expect(result?.resourceName).toBe('TestRdsCluster');
      expect(result?.issue).toContain('RDS Aurora Cluster does not have Backtrack enabled');
      expect(result?.fix).toContain('Set BacktrackWindow to a value greater than 0');
    });

    it('should flag RDS cluster with BacktrackWindow set to a negative value', () => {
      // Arrange
      const rdsCluster = createRdsClusterResource({
        BacktrackWindow: -1
      });
      
      // Act
      const result = rule.evaluate(rdsCluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBCluster');
      expect(result?.resourceName).toBe('TestRdsCluster');
      expect(result?.issue).toContain('RDS Aurora Cluster does not have Backtrack enabled');
    });

    it('should not flag RDS cluster with BacktrackWindow set to a positive value', () => {
      // Arrange
      const rdsCluster = createRdsClusterResource({
        BacktrackWindow: 24 // 24 hours backtrack window
      });
      
      // Act
      const result = rule.evaluate(rdsCluster, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag RDS cluster with BacktrackWindow set to minimum allowed value', () => {
      // Arrange
      const rdsCluster = createRdsClusterResource({
        BacktrackWindow: 1 // Minimum positive value
      });
      
      // Act
      const result = rule.evaluate(rdsCluster, stackName);
      
      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Arrange
      const rdsCluster = {
        Type: 'AWS::RDS::DBCluster',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      // Act
      const result = rule.evaluate(rdsCluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('RDS Aurora Cluster does not have Backtrack enabled');
    });

    it('should ignore non-applicable resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::RDS::DBInstance',
        Properties: {
          Engine: 'mysql',
          DBInstanceClass: 'db.t3.micro'
        },
        LogicalId: 'TestRdsInstance'
      };
      
      // Act
      const result = rule.evaluate(resource, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should handle BacktrackWindow as a reference', () => {
      // Arrange
      const rdsCluster = createRdsClusterResource({
        BacktrackWindow: { Ref: 'BacktrackWindowParam' }
      });
      
      // Act
      const result = rule.evaluate(rdsCluster, stackName);
      
      // Assert
      // The current implementation treats references as valid values
      // This test documents the current behavior, though in a real-world scenario
      // we might want to enhance the rule to validate references
      expect(result).toBeNull();
    });

    it('should handle BacktrackWindow as a CloudFormation function', () => {
      // Arrange
      const rdsCluster = createRdsClusterResource({
        BacktrackWindow: { 'Fn::FindInMap': ['BacktrackWindowMap', 'Production', 'Value'] }
      });
      
      // Act
      const result = rule.evaluate(rdsCluster, stackName);
      
      // Assert
      // The current implementation treats CloudFormation functions as valid values
      // This test documents the current behavior, though in a real-world scenario
      // we might want to enhance the rule to validate intrinsic functions
      expect(result).toBeNull();
    });
  });

  describe('Different Engine Types', () => {
    it('should check BacktrackWindow for Aurora MySQL', () => {
      // Arrange
      const rdsCluster = createRdsClusterResource({
        Engine: 'aurora-mysql',
        BacktrackWindow: 0
      });
      
      // Act
      const result = rule.evaluate(rdsCluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('RDS Aurora Cluster does not have Backtrack enabled');
    });

    it('should check BacktrackWindow for Aurora PostgreSQL', () => {
      // Arrange
      const rdsCluster = createRdsClusterResource({
        Engine: 'aurora-postgresql',
        BacktrackWindow: 0
      });
      
      // Act
      const result = rule.evaluate(rdsCluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('RDS Aurora Cluster does not have Backtrack enabled');
    });
  });
});
