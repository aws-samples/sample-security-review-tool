import { describe, it, expect } from 'vitest';
import { NetVpc002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/vpc/002-routing-tables.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('NetVpc002Rule', () => {
  const rule = new NetVpc002Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return null if allResources is not provided', () => {
      // Arrange
      const routeTable: CloudFormationResource = {
        Type: 'AWS::EC2::RouteTable',
        Properties: {
          VpcId: { Ref: 'TestVpc' }
        },
        LogicalId: 'TestRouteTable'
      };

      // Act
      const result = rule.evaluate(routeTable, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null if Properties is missing', () => {
      // Arrange
      const routeTable: CloudFormationResource = {
        Type: 'AWS::EC2::RouteTable',
        Properties: {},
        LogicalId: 'TestRouteTable'
      };

      // Act
      const result = rule.evaluate(routeTable, stackName, [routeTable]);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null if the resource is not a route table or route', () => {
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

    it('should return null for a route table with no routes', () => {
      // Arrange
      const routeTable: CloudFormationResource = {
        Type: 'AWS::EC2::RouteTable',
        Properties: {
          VpcId: { Ref: 'TestVpc' }
        },
        LogicalId: 'TestRouteTable'
      };

      // Act
      const result = rule.evaluate(routeTable, stackName, [routeTable]);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null for a route table with a default route to an Internet Gateway associated with a public subnet', () => {
      // Arrange
      const routeTable: CloudFormationResource = {
        Type: 'AWS::EC2::RouteTable',
        Properties: {
          VpcId: { Ref: 'TestVpc' }
        },
        LogicalId: 'TestRouteTable'
      };

      const route: CloudFormationResource = {
        Type: 'AWS::EC2::Route',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          DestinationCidrBlock: '0.0.0.0/0',
          GatewayId: { Ref: 'TestInternetGateway' }
        },
        LogicalId: 'TestRoute'
      };

      const association: CloudFormationResource = {
        Type: 'AWS::EC2::SubnetRouteTableAssociation',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          SubnetId: { Ref: 'TestSubnet' }
        },
        LogicalId: 'TestAssociation'
      };

      const subnet: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.0.0/24',
          MapPublicIpOnLaunch: true // Public subnet
        },
        LogicalId: 'TestSubnet'
      };

      const internetGateway: CloudFormationResource = {
        Type: 'AWS::EC2::InternetGateway',
        Properties: {},
        LogicalId: 'TestInternetGateway'
      };

      // Act
      const result = rule.evaluate(routeTable, stackName, [routeTable, route, association, subnet, internetGateway]);

      // Assert
      expect(result).toBeNull();
    });

    it('should return a finding for a route table with a default route to an Internet Gateway associated with a private subnet', () => {
      // Arrange
      const routeTable: CloudFormationResource = {
        Type: 'AWS::EC2::RouteTable',
        Properties: {
          VpcId: { Ref: 'TestVpc' }
        },
        LogicalId: 'TestRouteTable'
      };

      const route: CloudFormationResource = {
        Type: 'AWS::EC2::Route',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          DestinationCidrBlock: '0.0.0.0/0',
          GatewayId: { Ref: 'TestInternetGateway' }
        },
        LogicalId: 'TestRoute'
      };

      const association: CloudFormationResource = {
        Type: 'AWS::EC2::SubnetRouteTableAssociation',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          SubnetId: { Ref: 'TestSubnet' }
        },
        LogicalId: 'TestAssociation'
      };

      const subnet: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.0.0/24',
          MapPublicIpOnLaunch: false // Private subnet
        },
        LogicalId: 'TestSubnet'
      };

      const internetGateway: CloudFormationResource = {
        Type: 'AWS::EC2::InternetGateway',
        Properties: {},
        LogicalId: 'TestInternetGateway'
      };

      // Act
      const result = rule.evaluate(routeTable, stackName, [routeTable, route, association, subnet, internetGateway]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::RouteTable');
      expect(result?.resourceName).toBe('TestRouteTable');
      expect(result?.issue).toContain('Route table has a default route to an Internet Gateway and is associated with private subnet TestSubnet');
      expect(result?.fix).toContain('Create a separate route table for private subnets that uses a NAT Gateway instead of an Internet Gateway for outbound internet access');
    });

    it('should return null for a route with a default route to an Internet Gateway (handled by route table check)', () => {
      // Arrange
      const route: CloudFormationResource = {
        Type: 'AWS::EC2::Route',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          DestinationCidrBlock: '0.0.0.0/0',
          GatewayId: { Ref: 'TestInternetGateway' }
        },
        LogicalId: 'TestRoute'
      };

      const routeTable: CloudFormationResource = {
        Type: 'AWS::EC2::RouteTable',
        Properties: {
          VpcId: { Ref: 'TestVpc' }
        },
        LogicalId: 'TestRouteTable'
      };

      const association: CloudFormationResource = {
        Type: 'AWS::EC2::SubnetRouteTableAssociation',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          SubnetId: { Ref: 'TestSubnet' }
        },
        LogicalId: 'TestAssociation'
      };

      const subnet: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.0.0/24',
          MapPublicIpOnLaunch: false // Private subnet
        },
        LogicalId: 'PrivateSubnet' // Explicitly name it as private for the test
      };

      const internetGateway: CloudFormationResource = {
        Type: 'AWS::EC2::InternetGateway',
        Properties: {},
        LogicalId: 'TestInternetGateway'
      };

      // Act
      const result = rule.evaluate(route, stackName, [route, routeTable, association, subnet, internetGateway]);

      // Assert
      // The rule now checks at the route table level, not the individual route level
      expect(result).toBeNull();
    });

    it('should return a finding when a route contains intrinsic functions that cannot be evaluated', () => {
      // Arrange
      const route: CloudFormationResource = {
        Type: 'AWS::EC2::Route',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          DestinationCidrBlock: { Ref: 'DestinationCidrBlockParam' }, // Intrinsic function
          GatewayId: { Ref: 'TestInternetGateway' }
        },
        LogicalId: 'TestRoute'
      };

      // Act
      const result = rule.evaluate(route, stackName, [route]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::Route');
      expect(result?.resourceName).toBe('TestRoute');
      expect(result?.issue).toContain('Route contains CloudFormation intrinsic functions that cannot be evaluated at scan-time');
    });

    it('should return null for a route with a default IPv6 route (handled by route table check)', () => {
      // Arrange
      const route: CloudFormationResource = {
        Type: 'AWS::EC2::Route',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          DestinationIpv6CidrBlock: '::/0',
          GatewayId: { Ref: 'TestInternetGateway' } // Not an Egress-Only Internet Gateway
        },
        LogicalId: 'TestRoute'
      };

      const routeTable: CloudFormationResource = {
        Type: 'AWS::EC2::RouteTable',
        Properties: {
          VpcId: { Ref: 'TestVpc' }
        },
        LogicalId: 'TestRouteTable'
      };

      const association: CloudFormationResource = {
        Type: 'AWS::EC2::SubnetRouteTableAssociation',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          SubnetId: { Ref: 'TestSubnet' }
        },
        LogicalId: 'TestAssociation'
      };

      const subnet: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.0.0/24',
          MapPublicIpOnLaunch: false // Private subnet
        },
        LogicalId: 'PrivateSubnet' // Explicitly name it as private for the test
      };

      const internetGateway: CloudFormationResource = {
        Type: 'AWS::EC2::InternetGateway',
        Properties: {},
        LogicalId: 'TestInternetGateway'
      };

      // Act
      const result = rule.evaluate(route, stackName, [route, routeTable, association, subnet, internetGateway]);

      // Assert
      // The rule now checks at the route table level, not the individual route level
      expect(result).toBeNull();
    });

    it('should return null for a route with a default route to a NAT Gateway associated with a private subnet', () => {
      // Arrange
      const route: CloudFormationResource = {
        Type: 'AWS::EC2::Route',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          DestinationCidrBlock: '0.0.0.0/0',
          NatGatewayId: { Ref: 'TestNatGateway' }
        },
        LogicalId: 'TestRoute'
      };

      const routeTable: CloudFormationResource = {
        Type: 'AWS::EC2::RouteTable',
        Properties: {
          VpcId: { Ref: 'TestVpc' }
        },
        LogicalId: 'TestRouteTable'
      };

      const association: CloudFormationResource = {
        Type: 'AWS::EC2::SubnetRouteTableAssociation',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          SubnetId: { Ref: 'TestSubnet' }
        },
        LogicalId: 'TestAssociation'
      };

      const subnet: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.0.0/24',
          MapPublicIpOnLaunch: false // Private subnet
        },
        LogicalId: 'TestSubnet'
      };

      const natGateway: CloudFormationResource = {
        Type: 'AWS::EC2::NatGateway',
        Properties: {
          AllocationId: { 'Fn::GetAtt': ['TestEIP', 'AllocationId'] },
          SubnetId: { Ref: 'TestPublicSubnet' }
        },
        LogicalId: 'TestNatGateway'
      };

      // Act
      const result = rule.evaluate(route, stackName, [route, routeTable, association, subnet, natGateway]);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null for a route with a default IPv6 route using an Egress-Only Internet Gateway associated with a private subnet', () => {
      // Arrange
      const route: CloudFormationResource = {
        Type: 'AWS::EC2::Route',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          DestinationIpv6CidrBlock: '::/0',
          EgressOnlyInternetGatewayId: { Ref: 'TestEgressOnlyInternetGateway' }
        },
        LogicalId: 'TestRoute'
      };

      const routeTable: CloudFormationResource = {
        Type: 'AWS::EC2::RouteTable',
        Properties: {
          VpcId: { Ref: 'TestVpc' }
        },
        LogicalId: 'TestRouteTable'
      };

      const association: CloudFormationResource = {
        Type: 'AWS::EC2::SubnetRouteTableAssociation',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          SubnetId: { Ref: 'TestSubnet' }
        },
        LogicalId: 'TestAssociation'
      };

      const subnet: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.0.0/24',
          MapPublicIpOnLaunch: false // Private subnet
        },
        LogicalId: 'TestSubnet'
      };

      const egressOnlyInternetGateway: CloudFormationResource = {
        Type: 'AWS::EC2::EgressOnlyInternetGateway',
        Properties: {
          VpcId: { Ref: 'TestVpc' }
        },
        LogicalId: 'TestEgressOnlyInternetGateway'
      };

      // Act
      const result = rule.evaluate(route, stackName, [route, routeTable, association, subnet, egressOnlyInternetGateway]);

      // Assert
      expect(result).toBeNull();
    });

    it('should identify private subnets by naming convention', () => {
      // Arrange
      const routeTable: CloudFormationResource = {
        Type: 'AWS::EC2::RouteTable',
        Properties: {
          VpcId: { Ref: 'TestVpc' }
        },
        LogicalId: 'TestRouteTable'
      };

      const route: CloudFormationResource = {
        Type: 'AWS::EC2::Route',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          DestinationCidrBlock: '0.0.0.0/0',
          GatewayId: { Ref: 'TestInternetGateway' }
        },
        LogicalId: 'TestRoute'
      };

      const association: CloudFormationResource = {
        Type: 'AWS::EC2::SubnetRouteTableAssociation',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          SubnetId: { Ref: 'PrivateSubnet' }
        },
        LogicalId: 'TestAssociation'
      };

      const subnet: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.0.0/24',
          MapPublicIpOnLaunch: false // Explicitly set to false for the test
        },
        LogicalId: 'PrivateSubnet' // Private subnet by naming convention
      };

      const internetGateway: CloudFormationResource = {
        Type: 'AWS::EC2::InternetGateway',
        Properties: {},
        LogicalId: 'TestInternetGateway'
      };

      // Act
      const result = rule.evaluate(routeTable, stackName, [routeTable, route, association, subnet, internetGateway]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::RouteTable');
      expect(result?.resourceName).toBe('TestRouteTable');
      expect(result?.issue).toContain('Route table has a default route to an Internet Gateway and is associated with private subnet PrivateSubnet');
      expect(result?.fix).toContain('Create a separate route table for private subnets that uses a NAT Gateway instead of an Internet Gateway for outbound internet access');
    });

    it('should identify private subnets by CIDR block pattern', () => {
      // Arrange
      const routeTable: CloudFormationResource = {
        Type: 'AWS::EC2::RouteTable',
        Properties: {
          VpcId: { Ref: 'TestVpc' }
        },
        LogicalId: 'TestRouteTable'
      };

      const route: CloudFormationResource = {
        Type: 'AWS::EC2::Route',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          DestinationCidrBlock: '0.0.0.0/0',
          GatewayId: { Ref: 'TestInternetGateway' }
        },
        LogicalId: 'TestRoute'
      };

      const association: CloudFormationResource = {
        Type: 'AWS::EC2::SubnetRouteTableAssociation',
        Properties: {
          RouteTableId: { Ref: 'TestRouteTable' },
          SubnetId: { Ref: 'TestSubnet' }
        },
        LogicalId: 'TestAssociation'
      };

      const subnet: CloudFormationResource = {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: { Ref: 'TestVpc' },
          CidrBlock: '10.0.128.0/24', // Private subnet by CIDR pattern (third octet >= 128)
          MapPublicIpOnLaunch: false // Explicitly set to false for the test
        },
        LogicalId: 'TestSubnet'
      };

      const internetGateway: CloudFormationResource = {
        Type: 'AWS::EC2::InternetGateway',
        Properties: {},
        LogicalId: 'TestInternetGateway'
      };

      // Act
      const result = rule.evaluate(routeTable, stackName, [routeTable, route, association, subnet, internetGateway]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::RouteTable');
      expect(result?.resourceName).toBe('TestRouteTable');
      expect(result?.issue).toContain('Route table has a default route to an Internet Gateway and is associated with private subnet TestSubnet');
      expect(result?.fix).toContain('Create a separate route table for private subnets that uses a NAT Gateway instead of an Internet Gateway for outbound internet access');
    });
  });
});
