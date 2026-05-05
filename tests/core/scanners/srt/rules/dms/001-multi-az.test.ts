import { describe, it, expect } from 'vitest';
import { DMS001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/dms/001-multi-az.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('DMS001Rule', () => {
  const rule = new DMS001Rule();
  const stackName = 'test-stack';

  // Helper function to create DMS replication instance test resources
  function createDMSReplicationInstanceResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::DMS::ReplicationInstance',
      Properties: {
        ReplicationInstanceClass: 'dms.t3.medium',
        ...props
      },
      LogicalId: props.LogicalId || 'TestDMSReplicationInstance'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('DMS-001');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to DMS replication instance resources', () => {
      expect(rule.appliesTo('AWS::DMS::ReplicationInstance')).toBe(true);
      expect(rule.appliesTo('AWS::RDS::DBInstance')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('DMS Replication Instance Tests', () => {
    it('should flag instance with missing MultiAZ property', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource();
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::DMS::ReplicationInstance');
      expect(result?.resourceName).toBe('TestDMSReplicationInstance');
      expect(result?.issue).toContain('DMS replication instance is not configured with multi-AZ deployment');
      expect(result?.fix).toContain('Add MultiAZ property and set it to true');
    });

    it('should flag instance with MultiAZ set to false', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource({
        MultiAZ: false
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DMS replication instance is not configured with multi-AZ deployment');
      expect(result?.fix).toContain('Set MultiAZ property to true');
    });

    it('should flag instance with MultiAZ set to string "false"', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource({
        MultiAZ: 'false'
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DMS replication instance is not configured with multi-AZ deployment');
      expect(result?.fix).toContain('Set MultiAZ property to true');
    });

    it('should not flag instance with MultiAZ set to true', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource({
        MultiAZ: true
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag instance with MultiAZ set to string "true"', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource({
        MultiAZ: 'true'
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should flag instance with MultiAZ as CloudFormation intrinsic function', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource({
        MultiAZ: { Ref: 'MultiAZParameter' }
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DMS replication instance is not configured with multi-AZ deployment');
      expect(result?.fix).toContain('Set MultiAZ property to an explicit boolean value (true) rather than using CloudFormation functions');
    });

    it('should flag instance with MultiAZ set to unexpected value', () => {
      // Arrange
      const instance = createDMSReplicationInstanceResource({
        MultiAZ: 'invalid'
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DMS replication instance is not configured with multi-AZ deployment');
      expect(result?.fix).toContain('Set MultiAZ property to true');
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Arrange
      const instance = {
        Type: 'AWS::DMS::ReplicationInstance',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DMS replication instance is not configured with multi-AZ deployment');
      expect(result?.fix).toContain('Configure MultiAZ property to true');
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
