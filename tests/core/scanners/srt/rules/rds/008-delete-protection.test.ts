import { describe, it, expect } from 'vitest';
import { Rds008Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/rds/008-delete-protection.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Rds008Rule', () => {
  const rule = new Rds008Rule();
  const stackName = 'test-stack';

  // Helper function to create RDS DBInstance test resources
  function createRdsInstanceResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::RDS::DBInstance',
      Properties: {
        Engine: 'mysql',
        DBInstanceClass: 'db.t3.micro',
        AllocatedStorage: 20,
        MasterUsername: 'admin',
        MasterUserPassword: 'password',
        ...props
      },
      LogicalId: props.LogicalId || 'TestRdsInstance'
    };
  }

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
      expect(rule.id).toBe('RDS-008');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to RDS instance and cluster resources', () => {
      expect(rule.appliesTo('AWS::RDS::DBInstance')).toBe(true);
      expect(rule.appliesTo('AWS::RDS::DBCluster')).toBe(true);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('RDS Instance Tests', () => {
    it('should flag RDS instance without deletion protection', () => {
      // Arrange
      const rdsInstance = createRdsInstanceResource();
      
      // Act
      const result = rule.evaluate(rdsInstance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBInstance');
      expect(result?.resourceName).toBe('TestRdsInstance');
      expect(result?.issue).toContain('RDS Database does not have delete protection enabled');
    });

    it('should flag RDS instance with deletion protection explicitly set to false', () => {
      // Arrange
      const rdsInstance = createRdsInstanceResource({
        DeletionProtection: false
      });
      
      // Act
      const result = rule.evaluate(rdsInstance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBInstance');
      expect(result?.resourceName).toBe('TestRdsInstance');
      expect(result?.issue).toContain('RDS Database does not have delete protection enabled');
    });

    it('should not flag RDS instance with deletion protection enabled', () => {
      // Arrange
      const rdsInstance = createRdsInstanceResource({
        DeletionProtection: true
      });
      
      // Act
      const result = rule.evaluate(rdsInstance, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag RDS instance that belongs to a cluster', () => {
      // Arrange
      const rdsInstance = createRdsInstanceResource({
        DBClusterIdentifier: { Ref: 'TestRdsCluster' }
      });
      
      // Act
      const result = rule.evaluate(rdsInstance, stackName);
      
      // Assert
      expect(result).toBeNull();
    });
  });

  describe('RDS Cluster Tests', () => {
    it('should flag RDS cluster without deletion protection', () => {
      // Arrange
      const rdsCluster = createRdsClusterResource();
      
      // Act
      const result = rule.evaluate(rdsCluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBCluster');
      expect(result?.resourceName).toBe('TestRdsCluster');
      expect(result?.issue).toContain('RDS Database does not have delete protection enabled');
    });

    it('should flag RDS cluster with deletion protection explicitly set to false', () => {
      // Arrange
      const rdsCluster = createRdsClusterResource({
        DeletionProtection: false
      });
      
      // Act
      const result = rule.evaluate(rdsCluster, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBCluster');
      expect(result?.resourceName).toBe('TestRdsCluster');
      expect(result?.issue).toContain('RDS Database does not have delete protection enabled');
    });

    it('should not flag RDS cluster with deletion protection enabled', () => {
      // Arrange
      const rdsCluster = createRdsClusterResource({
        DeletionProtection: true
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
      const rdsInstance = {
        Type: 'AWS::RDS::DBInstance',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      // Act
      const result = rule.evaluate(rdsInstance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('RDS Database does not have delete protection enabled');
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
