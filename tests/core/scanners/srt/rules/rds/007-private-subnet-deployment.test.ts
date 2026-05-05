import { describe, it, expect } from 'vitest';
import { Rds007Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/rds/007-private-subnet-deployment.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Rds007Rule', () => {
  const rule = new Rds007Rule();
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

  // Helper function to create DBSubnetGroup test resources
  function createDbSubnetGroupResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::RDS::DBSubnetGroup',
      Properties: {
        DBSubnetGroupDescription: 'Test DB Subnet Group',
        SubnetIds: [
          { Ref: 'PrivateSubnet1' },
          { Ref: 'PrivateSubnet2' }
        ],
        ...props
      },
      LogicalId: props.LogicalId || 'TestDbSubnetGroup'
    };
  }

  // Helper function to create Subnet test resources
  function createSubnetResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::Subnet',
      Properties: {
        VpcId: { Ref: 'TestVPC' },
        CidrBlock: '10.0.0.0/24',
        AvailabilityZone: 'us-east-1a',
        ...props
      },
      LogicalId: props.LogicalId || 'TestSubnet'
    };
  }

  // Helper function to create VPC test resources
  function createVpcResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::VPC',
      Properties: {
        CidrBlock: '10.0.0.0/16',
        ...props
      },
      LogicalId: props.LogicalId || 'TestVPC'
    };
  }

  // Helper function to create RouteTable test resources
  function createRouteTableResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::RouteTable',
      Properties: {
        VpcId: { Ref: 'TestVPC' },
        ...props
      },
      LogicalId: props.LogicalId || 'TestRouteTable'
    };
  }

  // Helper function to create SubnetRouteTableAssociation test resources
  function createSubnetRouteTableAssociationResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::SubnetRouteTableAssociation',
      Properties: {
        SubnetId: { Ref: 'TestSubnet' },
        RouteTableId: { Ref: 'TestRouteTable' },
        ...props
      },
      LogicalId: props.LogicalId || 'TestSubnetRouteTableAssociation'
    };
  }

  // Helper function to create Route test resources
  function createRouteResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::Route',
      Properties: {
        RouteTableId: { Ref: 'TestRouteTable' },
        DestinationCidrBlock: '0.0.0.0/0',
        GatewayId: { Ref: 'TestInternetGateway' },
        ...props
      },
      LogicalId: props.LogicalId || 'TestRoute'
    };
  }

  // Helper function to create InternetGateway test resources
  function createInternetGatewayResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::InternetGateway',
      Properties: {
        ...props
      },
      LogicalId: props.LogicalId || 'TestInternetGateway'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('RDS-007');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to RDS instance and cluster resources', () => {
      expect(rule.appliesTo('AWS::RDS::DBInstance')).toBe(true);
      expect(rule.appliesTo('AWS::RDS::DBCluster')).toBe(true);
      expect(rule.appliesTo('AWS::EC2::Subnet')).toBe(false);
    });
  });

  describe('RDS Instance Tests', () => {
    it('should flag RDS instance without a subnet group', () => {
      // Arrange
      const rdsInstance = createRdsInstanceResource();
      const allResources = [rdsInstance];

      // Act
      const result = rule.evaluate(rdsInstance, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBInstance');
      expect(result?.resourceName).toBe('TestRdsInstance');
      expect(result?.issue).toContain('RDS Database deployed in public subnet');
      expect(result?.fix).toContain('Specify a DBSubnetGroupName with private subnets only');
    });

    it('should not flag RDS instance with a subnet group in private subnets', () => {
      // Arrange
      const vpc = createVpcResource();
      const privateSubnet1 = createSubnetResource({
        LogicalId: 'PrivateSubnet1',
        MapPublicIpOnLaunch: false
      });
      const privateSubnet2 = createSubnetResource({
        LogicalId: 'PrivateSubnet2',
        MapPublicIpOnLaunch: false
      });
      const privateRouteTable = createRouteTableResource({
        LogicalId: 'PrivateRouteTable'
      });
      const privateSubnetRouteTableAssociation1 = createSubnetRouteTableAssociationResource({
        LogicalId: 'PrivateSubnetRouteTableAssociation1',
        SubnetId: { Ref: 'PrivateSubnet1' },
        RouteTableId: { Ref: 'PrivateRouteTable' }
      });
      const privateSubnetRouteTableAssociation2 = createSubnetRouteTableAssociationResource({
        LogicalId: 'PrivateSubnetRouteTableAssociation2',
        SubnetId: { Ref: 'PrivateSubnet2' },
        RouteTableId: { Ref: 'PrivateRouteTable' }
      });
      const dbSubnetGroup = createDbSubnetGroupResource();
      const rdsInstance = createRdsInstanceResource({
        DBSubnetGroupName: { Ref: 'TestDbSubnetGroup' }
      });

      const allResources = [
        vpc,
        privateSubnet1,
        privateSubnet2,
        privateRouteTable,
        privateSubnetRouteTableAssociation1,
        privateSubnetRouteTableAssociation2,
        dbSubnetGroup,
        rdsInstance
      ];

      // Act
      const result = rule.evaluate(rdsInstance, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should flag RDS instance with a subnet group in public subnets', () => {
      // Arrange
      const vpc = createVpcResource();
      const publicSubnet1 = createSubnetResource({
        LogicalId: 'PrivateSubnet1',
        MapPublicIpOnLaunch: true
      });
      const publicSubnet2 = createSubnetResource({
        LogicalId: 'PrivateSubnet2',
        MapPublicIpOnLaunch: true
      });
      const publicRouteTable = createRouteTableResource({
        LogicalId: 'PublicRouteTable'
      });
      const publicSubnetRouteTableAssociation1 = createSubnetRouteTableAssociationResource({
        LogicalId: 'PublicSubnetRouteTableAssociation1',
        SubnetId: { Ref: 'PrivateSubnet1' },
        RouteTableId: { Ref: 'PublicRouteTable' }
      });
      const publicSubnetRouteTableAssociation2 = createSubnetRouteTableAssociationResource({
        LogicalId: 'PublicSubnetRouteTableAssociation2',
        SubnetId: { Ref: 'PrivateSubnet2' },
        RouteTableId: { Ref: 'PublicRouteTable' }
      });
      const dbSubnetGroup = createDbSubnetGroupResource();
      const rdsInstance = createRdsInstanceResource({
        DBSubnetGroupName: { Ref: 'TestDbSubnetGroup' }
      });

      const allResources = [
        vpc,
        publicSubnet1,
        publicSubnet2,
        publicRouteTable,
        publicSubnetRouteTableAssociation1,
        publicSubnetRouteTableAssociation2,
        dbSubnetGroup,
        rdsInstance
      ];

      // Act
      const result = rule.evaluate(rdsInstance, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBInstance');
      expect(result?.resourceName).toBe('TestRdsInstance');
      expect(result?.issue).toContain('RDS Database deployed in public subnet');
      expect(result?.fix).toContain('Use a subnet group with private subnets only');
    });

    it('should flag RDS instance with a subnet group containing a subnet with route to internet gateway', () => {
      // Arrange
      const vpc = createVpcResource();
      const privateSubnet1 = createSubnetResource({
        LogicalId: 'PrivateSubnet1',
        MapPublicIpOnLaunch: false
      });
      const publicSubnet2 = createSubnetResource({
        LogicalId: 'PrivateSubnet2',
        MapPublicIpOnLaunch: false
      });
      const privateRouteTable = createRouteTableResource({
        LogicalId: 'PrivateRouteTable'
      });
      const publicRouteTable = createRouteTableResource({
        LogicalId: 'PublicRouteTable'
      });
      const privateSubnetRouteTableAssociation = createSubnetRouteTableAssociationResource({
        LogicalId: 'PrivateSubnetRouteTableAssociation',
        SubnetId: { Ref: 'PrivateSubnet1' },
        RouteTableId: { Ref: 'PrivateRouteTable' }
      });
      const publicSubnetRouteTableAssociation = createSubnetRouteTableAssociationResource({
        LogicalId: 'PublicSubnetRouteTableAssociation',
        SubnetId: { Ref: 'PrivateSubnet2' },
        RouteTableId: { Ref: 'PublicRouteTable' }
      });
      const internetGateway = createInternetGatewayResource();
      const publicRoute = createRouteResource({
        RouteTableId: { Ref: 'PublicRouteTable' },
        GatewayId: { Ref: 'TestInternetGateway' }
      });
      const dbSubnetGroup = createDbSubnetGroupResource();
      const rdsInstance = createRdsInstanceResource({
        DBSubnetGroupName: { Ref: 'TestDbSubnetGroup' }
      });

      const allResources = [
        vpc,
        privateSubnet1,
        publicSubnet2,
        privateRouteTable,
        publicRouteTable,
        privateSubnetRouteTableAssociation,
        publicSubnetRouteTableAssociation,
        internetGateway,
        publicRoute,
        dbSubnetGroup,
        rdsInstance
      ];

      // Act
      const result = rule.evaluate(rdsInstance, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBInstance');
      expect(result?.resourceName).toBe('TestRdsInstance');
      expect(result?.issue).toContain('RDS Database deployed in public subnet');
    });
  });

  describe('RDS Cluster Tests', () => {
    it('should flag RDS cluster without a subnet group', () => {
      // Arrange
      const rdsCluster = createRdsClusterResource();
      const allResources = [rdsCluster];

      // Act
      const result = rule.evaluate(rdsCluster, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBCluster');
      expect(result?.resourceName).toBe('TestRdsCluster');
      expect(result?.issue).toContain('RDS Database deployed in public subnet');
      expect(result?.fix).toContain('Specify a DBSubnetGroupName with private subnets only');
    });

    it('should not flag RDS cluster with a subnet group in private subnets', () => {
      // Arrange
      const vpc = createVpcResource();
      const privateSubnet1 = createSubnetResource({
        LogicalId: 'PrivateSubnet1',
        MapPublicIpOnLaunch: false
      });
      const privateSubnet2 = createSubnetResource({
        LogicalId: 'PrivateSubnet2',
        MapPublicIpOnLaunch: false
      });
      const privateRouteTable = createRouteTableResource({
        LogicalId: 'PrivateRouteTable'
      });
      const privateSubnetRouteTableAssociation1 = createSubnetRouteTableAssociationResource({
        LogicalId: 'PrivateSubnetRouteTableAssociation1',
        SubnetId: { Ref: 'PrivateSubnet1' },
        RouteTableId: { Ref: 'PrivateRouteTable' }
      });
      const privateSubnetRouteTableAssociation2 = createSubnetRouteTableAssociationResource({
        LogicalId: 'PrivateSubnetRouteTableAssociation2',
        SubnetId: { Ref: 'PrivateSubnet2' },
        RouteTableId: { Ref: 'PrivateRouteTable' }
      });
      const dbSubnetGroup = createDbSubnetGroupResource();
      const rdsCluster = createRdsClusterResource({
        DBSubnetGroupName: { Ref: 'TestDbSubnetGroup' }
      });

      const allResources = [
        vpc,
        privateSubnet1,
        privateSubnet2,
        privateRouteTable,
        privateSubnetRouteTableAssociation1,
        privateSubnetRouteTableAssociation2,
        dbSubnetGroup,
        rdsCluster
      ];

      // Act
      const result = rule.evaluate(rdsCluster, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should flag RDS cluster with a subnet group in public subnets', () => {
      // Arrange
      const vpc = createVpcResource();
      const publicSubnet1 = createSubnetResource({
        LogicalId: 'PrivateSubnet1',
        MapPublicIpOnLaunch: true
      });
      const publicSubnet2 = createSubnetResource({
        LogicalId: 'PrivateSubnet2',
        MapPublicIpOnLaunch: true
      });
      const publicRouteTable = createRouteTableResource({
        LogicalId: 'PublicRouteTable'
      });
      const publicSubnetRouteTableAssociation1 = createSubnetRouteTableAssociationResource({
        LogicalId: 'PublicSubnetRouteTableAssociation1',
        SubnetId: { Ref: 'PrivateSubnet1' },
        RouteTableId: { Ref: 'PublicRouteTable' }
      });
      const publicSubnetRouteTableAssociation2 = createSubnetRouteTableAssociationResource({
        LogicalId: 'PublicSubnetRouteTableAssociation2',
        SubnetId: { Ref: 'PrivateSubnet2' },
        RouteTableId: { Ref: 'PublicRouteTable' }
      });
      const dbSubnetGroup = createDbSubnetGroupResource();
      const rdsCluster = createRdsClusterResource({
        DBSubnetGroupName: { Ref: 'TestDbSubnetGroup' }
      });

      const allResources = [
        vpc,
        publicSubnet1,
        publicSubnet2,
        publicRouteTable,
        publicSubnetRouteTableAssociation1,
        publicSubnetRouteTableAssociation2,
        dbSubnetGroup,
        rdsCluster
      ];

      // Act
      const result = rule.evaluate(rdsCluster, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBCluster');
      expect(result?.resourceName).toBe('TestRdsCluster');
      expect(result?.issue).toContain('RDS Database deployed in public subnet');
      expect(result?.fix).toContain('Use a subnet group with private subnets only');
    });
  });

  describe('DB Cluster Instance Tests', () => {
    it('should ignore DB instances that belong to a DB cluster', () => {
      // Arrange
      const vpc = createVpcResource();
      const publicSubnet1 = createSubnetResource({
        LogicalId: 'PrivateSubnet1',
        MapPublicIpOnLaunch: true
      });
      const publicSubnet2 = createSubnetResource({
        LogicalId: 'PrivateSubnet2',
        MapPublicIpOnLaunch: true
      });
      const publicRouteTable = createRouteTableResource({
        LogicalId: 'PublicRouteTable'
      });
      const publicSubnetRouteTableAssociation1 = createSubnetRouteTableAssociationResource({
        LogicalId: 'PublicSubnetRouteTableAssociation1',
        SubnetId: { Ref: 'PrivateSubnet1' },
        RouteTableId: { Ref: 'PublicRouteTable' }
      });
      const publicSubnetRouteTableAssociation2 = createSubnetRouteTableAssociationResource({
        LogicalId: 'PublicSubnetRouteTableAssociation2',
        SubnetId: { Ref: 'PrivateSubnet2' },
        RouteTableId: { Ref: 'PublicRouteTable' }
      });
      const dbSubnetGroup = createDbSubnetGroupResource();
      const rdsCluster = createRdsClusterResource({
        LogicalId: 'TestRdsCluster',
        DBSubnetGroupName: { Ref: 'TestDbSubnetGroup' }
      });
      const rdsClusterInstance = createRdsInstanceResource({
        LogicalId: 'TestRdsClusterInstance',
        DBSubnetGroupName: { Ref: 'TestDbSubnetGroup' },
        DBClusterIdentifier: { Ref: 'TestRdsCluster' }
      });

      const allResources = [
        vpc,
        publicSubnet1,
        publicSubnet2,
        publicRouteTable,
        publicSubnetRouteTableAssociation1,
        publicSubnetRouteTableAssociation2,
        dbSubnetGroup,
        rdsCluster,
        rdsClusterInstance
      ];

      // Act
      // The cluster should be flagged
      const clusterResult = rule.evaluate(rdsCluster, stackName, allResources);
      // The cluster instance should be ignored
      const instanceResult = rule.evaluate(rdsClusterInstance, stackName, allResources);

      // Assert
      expect(clusterResult).not.toBeNull();
      expect(clusterResult?.resourceType).toBe('AWS::RDS::DBCluster');
      expect(clusterResult?.resourceName).toBe('TestRdsCluster');
      expect(clusterResult?.issue).toContain('RDS Database deployed in public subnet');
      
      // The instance should be ignored (return null) because it belongs to a cluster
      expect(instanceResult).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should return null if allResources is not provided', () => {
      // Arrange
      const rdsInstance = createRdsInstanceResource({
        DBSubnetGroupName: { Ref: 'TestDbSubnetGroup' }
      });

      // Act
      const result = rule.evaluate(rdsInstance, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle missing Properties', () => {
      // Arrange
      const rdsInstance = {
        Type: 'AWS::RDS::DBInstance',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      const allResources = [rdsInstance];

      // Act
      const result = rule.evaluate(rdsInstance, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('RDS Database deployed in public subnet');
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
      const result = rule.evaluate(resource, stackName, [resource]);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle subnet group that cannot be found', () => {
      // Arrange
      const rdsInstance = createRdsInstanceResource({
        DBSubnetGroupName: { Ref: 'NonExistentSubnetGroup' }
      });

      const allResources = [rdsInstance];

      // Act
      const result = rule.evaluate(rdsInstance, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle subnet group with no subnets', () => {
      // Arrange
      const dbSubnetGroup = createDbSubnetGroupResource({
        SubnetIds: []
      });
      const rdsInstance = createRdsInstanceResource({
        DBSubnetGroupName: { Ref: 'TestDbSubnetGroup' }
      });

      const allResources = [dbSubnetGroup, rdsInstance];

      // Act
      const result = rule.evaluate(rdsInstance, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle subnet that cannot be found', () => {
      // Arrange
      const dbSubnetGroup = createDbSubnetGroupResource({
        SubnetIds: [
          { Ref: 'NonExistentSubnet1' },
          { Ref: 'NonExistentSubnet2' }
        ]
      });
      const rdsInstance = createRdsInstanceResource({
        DBSubnetGroupName: { Ref: 'TestDbSubnetGroup' }
      });

      const allResources = [dbSubnetGroup, rdsInstance];

      // Act
      const result = rule.evaluate(rdsInstance, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });
  });
});
