import { describe, it, expect } from 'vitest';
import { Neptune001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/neptune/001-multi-az-configuration.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Neptune001Rule', () => {
  const rule = new Neptune001Rule();
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

  // Helper function to create Neptune DBSubnetGroup test resources
  function createSubnetGroupResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::Neptune::DBSubnetGroup',
      Properties: {
        DBSubnetGroupDescription: 'Test DB Subnet Group',
        SubnetIds: [
          { Ref: 'Subnet1' },
          { Ref: 'Subnet2' }
        ],
        ...props
      },
      LogicalId: props.LogicalId || 'TestSubnetGroup'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('NEPTUNE-001');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to Neptune DBCluster resources', () => {
      expect(rule.appliesTo('AWS::Neptune::DBCluster')).toBe(true);
      expect(rule.appliesTo('AWS::Neptune::DBInstance')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Cluster Identifier Tests', () => {
    it('should fail when DBClusterIdentifier is missing', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        DBClusterIdentifier: undefined
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune cluster not configured for multi-AZ deployment');
      expect(result?.fix).toContain('must have a valid DBClusterIdentifier');
    });

    it('should continue evaluation when DBClusterIdentifier is present', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        DBSubnetGroupName: 'TestSubnetGroup'
      });
      const instance1 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1a',
        LogicalId: 'NeptuneInstance1'
      });
      const instance2 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1b',
        LogicalId: 'NeptuneInstance2'
      });
      const subnetGroup = createSubnetGroupResource({
        LogicalId: 'TestSubnetGroup'
      });
      
      const allResources = [resource, instance1, instance2, subnetGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Associated Instances Tests', () => {
    it('should fail when no instances are associated with the cluster', () => {
      // Arrange
      const resource = createNeptuneClusterResource();
      const allResources = [resource];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune cluster not configured for multi-AZ deployment');
      expect(result?.fix).toContain('Create at least one Neptune DB instance');
    });

    it('should fail when only one instance is associated with the cluster', () => {
      // Arrange
      const resource = createNeptuneClusterResource();
      const instance = createNeptuneInstanceResource();
      const allResources = [resource, instance];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune cluster not configured for multi-AZ deployment');
      expect(result?.fix).toContain('Deploy at least one read replica');
    });

    it('should pass when multiple instances are associated with the cluster in different AZs', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        DBSubnetGroupName: 'TestSubnetGroup'
      });
      const instance1 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1a',
        LogicalId: 'NeptuneInstance1'
      });
      const instance2 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1b',
        LogicalId: 'NeptuneInstance2'
      });
      const subnetGroup = createSubnetGroupResource();
      
      const allResources = [resource, instance1, instance2, subnetGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Availability Zone Tests', () => {
    it('should fail when instances are in the same AZ', () => {
      // Arrange
      const resource = createNeptuneClusterResource();
      const instance1 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1a',
        LogicalId: 'NeptuneInstance1'
      });
      const instance2 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1a',
        LogicalId: 'NeptuneInstance2'
      });
      
      const allResources = [resource, instance1, instance2];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune cluster not configured for multi-AZ deployment');
      expect(result?.fix).toContain('Deploy Neptune instances across at least two different Availability Zones');
    });

    it('should pass when instances are in different AZs', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        DBSubnetGroupName: 'TestSubnetGroup'
      });
      const instance1 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1a',
        LogicalId: 'NeptuneInstance1'
      });
      const instance2 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1b',
        LogicalId: 'NeptuneInstance2'
      });
      const subnetGroup = createSubnetGroupResource();
      
      const allResources = [resource, instance1, instance2, subnetGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle CloudFormation references in AZ values', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        DBSubnetGroupName: 'TestSubnetGroup'
      });
      const instance1 = createNeptuneInstanceResource({
        AvailabilityZone: { Ref: 'AZ1' },
        LogicalId: 'NeptuneInstance1'
      });
      const instance2 = createNeptuneInstanceResource({
        AvailabilityZone: { Ref: 'AZ2' },
        LogicalId: 'NeptuneInstance2'
      });
      const subnetGroup = createSubnetGroupResource();
      
      const allResources = [resource, instance1, instance2, subnetGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle CloudFormation Fn::Select in AZ values', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        DBSubnetGroupName: 'TestSubnetGroup'
      });
      const instance1 = createNeptuneInstanceResource({
        AvailabilityZone: { 
          'Fn::Select': [0, { 'Fn::GetAZs': '' }]
        },
        LogicalId: 'NeptuneInstance1'
      });
      const instance2 = createNeptuneInstanceResource({
        AvailabilityZone: { 
          'Fn::Select': [1, { 'Fn::GetAZs': '' }]
        },
        LogicalId: 'NeptuneInstance2'
      });
      const subnetGroup = createSubnetGroupResource();
      
      const allResources = [resource, instance1, instance2, subnetGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Subnet Group Tests', () => {
    it('should fail when DBSubnetGroupName is missing', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        DBSubnetGroupName: undefined
      });
      const instance1 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1a',
        LogicalId: 'NeptuneInstance1'
      });
      const instance2 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1b',
        LogicalId: 'NeptuneInstance2'
      });
      
      const allResources = [resource, instance1, instance2];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune cluster not configured for multi-AZ deployment');
      expect(result?.fix).toContain('Specify a DBSubnetGroupName that spans multiple Availability Zones');
    });

    it('should fail when subnet group has fewer than 2 subnets', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        DBSubnetGroupName: { Ref: 'SingleSubnetGroup' }
      });
      const instance1 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1a',
        LogicalId: 'NeptuneInstance1'
      });
      const instance2 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1b',
        LogicalId: 'NeptuneInstance2'
      });
      const subnetGroup = createSubnetGroupResource({
        LogicalId: 'SingleSubnetGroup',
        SubnetIds: [
          { Ref: 'Subnet1' }
        ]
      });
      
      const allResources = [resource, instance1, instance2, subnetGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune cluster not configured for multi-AZ deployment');
      expect(result?.fix).toContain('Configure the Neptune DB subnet group to include subnets from at least two different Availability Zones');
    });

    it('should pass when subnet group has multiple subnets', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        DBSubnetGroupName: { Ref: 'MultiSubnetGroup' }
      });
      const instance1 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1a',
        LogicalId: 'NeptuneInstance1'
      });
      const instance2 = createNeptuneInstanceResource({
        AvailabilityZone: 'us-east-1b',
        LogicalId: 'NeptuneInstance2'
      });
      const subnetGroup = createSubnetGroupResource({
        LogicalId: 'MultiSubnetGroup',
        SubnetIds: [
          { Ref: 'Subnet1' },
          { Ref: 'Subnet2' }
        ]
      });
      
      const allResources = [resource, instance1, instance2, subnetGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
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
      expect(result?.issue).toContain('Neptune cluster not configured for multi-AZ deployment');
      expect(result?.fix).toContain('must have a valid DBClusterIdentifier');
    });

    it('should handle CloudFormation intrinsic functions in DBClusterIdentifier', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        DBClusterIdentifier: { Ref: 'ClusterName' },
        DBSubnetGroupName: 'TestSubnetGroup'
      });
      const instance1 = createNeptuneInstanceResource({
        DBClusterIdentifier: { Ref: 'ClusterName' },
        AvailabilityZone: 'us-east-1a',
        LogicalId: 'NeptuneInstance1'
      });
      const instance2 = createNeptuneInstanceResource({
        DBClusterIdentifier: { Ref: 'ClusterName' },
        AvailabilityZone: 'us-east-1b',
        LogicalId: 'NeptuneInstance2'
      });
      const subnetGroup = createSubnetGroupResource();
      
      const allResources = [resource, instance1, instance2, subnetGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
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
      // This test assumes the rule implementation checks applicability internally
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});
