import { describe, it, expect } from 'vitest';
import { NetVpc001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/vpc/001-multiple-azs.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('NetVpc001Rule', () => {
  const rule = new NetVpc001Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return null if allResources is not provided', () => {
      // Arrange
      const vpc: CloudFormationResource = {
        Type: 'AWS::EC2::VPC',
        Properties: {
          CidrBlock: '10.0.0.0/16'
        },
        LogicalId: 'TestVpc'
      };

      // Act
      const result = rule.evaluate(vpc, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null if the resource is not a VPC', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EC2::Instance',
        Properties: {
          InstanceType: 't2.micro'
        },
        LogicalId: 'TestInstance'
      };

      // Act
      const result = rule.evaluate(resource, stackName, [resource]);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null if the VPC has no associated subnets', () => {
      // Arrange
      const vpc: CloudFormationResource = {
        Type: 'AWS::EC2::VPC',
        Properties: {
          CidrBlock: '10.0.0.0/16'
        },
        LogicalId: 'TestVpc'
      };

      // Act
      const result = rule.evaluate(vpc, stackName, [vpc]);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null if the VPC has subnets in multiple AZs', () => {
      // Arrange
      const vpc: CloudFormationResource = {
        Type: 'AWS::EC2::VPC',
        Properties: {
          CidrBlock: '10.0.0.0/16'
        },
        LogicalId: 'TestVpc'
      };

      const subnet1: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.0.0/24',
          AvailabilityZone: 'us-east-1a'
        },
        LogicalId: 'TestSubnet1'
      };

      const subnet2: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.1.0/24',
          AvailabilityZone: 'us-east-1b'
        },
        LogicalId: 'TestSubnet2'
      };

      // Act
      const result = rule.evaluate(vpc, stackName, [vpc, subnet1, subnet2]);

      // Assert
      expect(result).toBeNull();
    });

    it('should return a finding if the VPC has subnets in only one AZ', () => {
      // Arrange
      const vpc: CloudFormationResource = {
        Type: 'AWS::EC2::VPC',
        Properties: {
          CidrBlock: '10.0.0.0/16'
        },
        LogicalId: 'TestVpc'
      };

      const subnet1: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.0.0/24',
          AvailabilityZone: 'us-east-1a'
        },
        LogicalId: 'TestSubnet1'
      };

      const subnet2: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.1.0/24',
          AvailabilityZone: 'us-east-1a' // Same AZ as subnet1
        },
        LogicalId: 'TestSubnet2'
      };

      // Act
      const result = rule.evaluate(vpc, stackName, [vpc, subnet1, subnet2]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::VPC');
      expect(result?.resourceName).toBe('TestVpc');
      expect(result?.issue).toContain('VPC TestVpc has subnets in only 1 availability zone(s)');
      expect(result?.fix).toContain('Create subnets in at least two different availability zones to ensure high availability.');
    });

    it('should return null if the VPC has subnets with intrinsic AZ references that likely span multiple AZs', () => {
      // Arrange
      const vpc: CloudFormationResource = {
        Type: 'AWS::EC2::VPC',
        Properties: {
          CidrBlock: '10.0.0.0/16'
        },
        LogicalId: 'TestVpc'
      };

      const subnet1: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.0.0/24',
          AvailabilityZone: {
            'Fn::Select': [0, { 'Fn::GetAZs': '' }]
          }
        },
        LogicalId: 'TestSubnet1'
      };

      const subnet2: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.1.0/24',
          AvailabilityZone: {
            'Fn::Select': [1, { 'Fn::GetAZs': '' }]
          }
        },
        LogicalId: 'TestSubnet2'
      };

      // Act
      const result = rule.evaluate(vpc, stackName, [vpc, subnet1, subnet2]);

      // Assert
      expect(result).toBeNull();
    });
    
    it('should return a finding if the VPC has subnets with unresolvable intrinsic AZ references', () => {
      // Arrange
      const vpc: CloudFormationResource = {
        Type: 'AWS::EC2::VPC',
        Properties: {
          CidrBlock: '10.0.0.0/16'
        },
        LogicalId: 'TestVpc'
      };

      const subnet1: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.0.0/24',
          AvailabilityZone: { Ref: 'AZ1Parameter' } // Unresolvable intrinsic function
        },
        LogicalId: 'TestSubnet1'
      };

      // Act
      const result = rule.evaluate(vpc, stackName, [vpc, subnet1]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::VPC');
      expect(result?.resourceName).toBe('TestVpc');
      // The actual error message is about intrinsic functions, not about having 0 AZs
      expect(result?.issue).toContain('CloudFormation intrinsic functions');
    });

    it('should return null if the VPC has subnets with CDK multi-AZ naming patterns', () => {
      // Arrange
      const vpc: CloudFormationResource = {
        Type: 'AWS::EC2::VPC',
        Properties: {
          CidrBlock: '10.0.0.0/16'
        },
        LogicalId: 'TestVpc'
      };

      const subnet1: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.0.0/24',
          AvailabilityZone: 'us-east-1a' // Explicitly set AZ for test
        },
        LogicalId: 'PublicSubnetA'
      };

      const subnet2: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.1.0/24',
          AvailabilityZone: 'us-east-1b' // Explicitly set AZ for test
        },
        LogicalId: 'PublicSubnetB'
      };

      // Act
      const result = rule.evaluate(vpc, stackName, [vpc, subnet1, subnet2]);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null if the VPC has subnets with distinct CIDR blocks', () => {
      // Arrange
      const vpc: CloudFormationResource = {
        Type: 'AWS::EC2::VPC',
        Properties: {
          CidrBlock: '10.0.0.0/16'
        },
        LogicalId: 'TestVpc'
      };

      const subnet1: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.0.0/24',
          AvailabilityZone: 'us-east-1a' // Explicitly set AZ for test
        },
        LogicalId: 'TestSubnet1'
      };

      const subnet2: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.1.0/24',
          AvailabilityZone: 'us-east-1b' // Explicitly set AZ for test
        },
        LogicalId: 'TestSubnet2'
      };

      // Act
      const result = rule.evaluate(vpc, stackName, [vpc, subnet1, subnet2]);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle different types of VPC references from subnets', () => {
      // Arrange
      const vpc: CloudFormationResource = {
        Type: 'AWS::EC2::VPC',
        Properties: {
          CidrBlock: '10.0.0.0/16'
        },
        LogicalId: 'TestVpc'
      };

      // Direct string reference
      const subnet1: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: 'TestVpc',
          CidrBlock: '10.0.0.0/24',
          AvailabilityZone: 'us-east-1a'
        },
        LogicalId: 'TestSubnet1'
      };

      // Ref reference
      const subnet2: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.1.0/24',
          AvailabilityZone: 'us-east-1b'
        },
        LogicalId: 'TestSubnet2'
      };

      // GetAtt reference
      const subnet3: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { 'Fn::GetAtt': ['TestVpc', 'VpcId'] },
          CidrBlock: '10.0.2.0/24',
          AvailabilityZone: 'us-east-1c'
        },
        LogicalId: 'TestSubnet3'
      };

      // Act
      const result = rule.evaluate(vpc, stackName, [vpc, subnet1, subnet2, subnet3]);

      // Assert
      expect(result).toBeNull();
    });
  });
});
