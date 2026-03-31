import { describe, it, expect } from 'vitest';
import { TG001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/transit-gateway/001-route-table-isolation.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('TG001Rule', () => {
  const rule = new TG001Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return null if allResources is not provided', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway'
        },
        LogicalId: 'TestTransitGateway'
      };

      // Act
      const result = rule.evaluate(transitGateway, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null if the resource is not a Transit Gateway related resource', () => {
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

    it('should return a finding if Transit Gateway has default route table association enabled', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway',
          DefaultRouteTableAssociation: 'enable'
        },
        LogicalId: 'TestTransitGateway'
      };

      // Act
      const result = rule.evaluate(transitGateway, stackName, [transitGateway]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::TransitGateway');
      expect(result?.resourceName).toBe('TestTransitGateway');
      expect(result?.issue).toContain('has default route table association enabled');
    });

    it('should return a finding if Transit Gateway has default route table propagation enabled', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway',
          DefaultRouteTableAssociation: 'disable',
          DefaultRouteTablePropagation: 'enable'
        },
        LogicalId: 'TestTransitGateway'
      };

      // Act
      const result = rule.evaluate(transitGateway, stackName, [transitGateway]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::TransitGateway');
      expect(result?.resourceName).toBe('TestTransitGateway');
      expect(result?.issue).toContain('has default route table propagation enabled');
    });

    it('should return a finding if Transit Gateway has multiple VPC attachments but only one route table', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway',
          DefaultRouteTableAssociation: 'disable',
          DefaultRouteTablePropagation: 'disable'
        },
        LogicalId: 'TestTransitGateway'
      };

      const routeTable: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' }
        },
        LogicalId: 'TestRouteTable'
      };

      const vpcAttachment1: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayAttachment',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' },
          VpcId: { Ref: 'TestVpc1' }
        },
        LogicalId: 'TestVpcAttachment1'
      };

      const vpcAttachment2: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayAttachment',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' },
          VpcId: { Ref: 'TestVpc2' }
        },
        LogicalId: 'TestVpcAttachment2'
      };

      // Act
      const result = rule.evaluate(transitGateway, stackName, [transitGateway, routeTable, vpcAttachment1, vpcAttachment2]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::TransitGateway');
      expect(result?.resourceName).toBe('TestTransitGateway');
      expect(result?.issue).toContain('has 2 VPC attachments but only 1 route table');
    });

    it('should return a finding if Transit Gateway has multiple VPC attachments but no route table associations', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway',
          DefaultRouteTableAssociation: 'disable',
          DefaultRouteTablePropagation: 'disable'
        },
        LogicalId: 'TestTransitGateway'
      };

      const routeTable1: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' }
        },
        LogicalId: 'TestRouteTable1'
      };

      const routeTable2: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' }
        },
        LogicalId: 'TestRouteTable2'
      };

      const vpcAttachment1: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayAttachment',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' },
          VpcId: { Ref: 'TestVpc1' }
        },
        LogicalId: 'TestVpcAttachment1'
      };

      const vpcAttachment2: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayAttachment',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' },
          VpcId: { Ref: 'TestVpc2' }
        },
        LogicalId: 'TestVpcAttachment2'
      };

      // Act
      const result = rule.evaluate(transitGateway, stackName, [transitGateway, routeTable1, routeTable2, vpcAttachment1, vpcAttachment2]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::TransitGateway');
      expect(result?.resourceName).toBe('TestTransitGateway');
      expect(result?.issue).toContain('has multiple VPC attachments but no explicit route table associations');
    });

    it('should return null if Transit Gateway has proper configuration with multiple route tables and associations', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway',
          DefaultRouteTableAssociation: 'disable',
          DefaultRouteTablePropagation: 'disable'
        },
        LogicalId: 'TestTransitGateway'
      };

      const routeTable1: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' }
        },
        LogicalId: 'TestRouteTable1'
      };

      const routeTable2: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' }
        },
        LogicalId: 'TestRouteTable2'
      };

      const vpcAttachment1: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayAttachment',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' },
          VpcId: { Ref: 'TestVpc1' }
        },
        LogicalId: 'TestVpcAttachment1'
      };

      const vpcAttachment2: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayAttachment',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' },
          VpcId: { Ref: 'TestVpc2' }
        },
        LogicalId: 'TestVpcAttachment2'
      };

      const association1: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTableAssociation',
        Properties: {
          TransitGatewayAttachmentId: { Ref: 'TestVpcAttachment1' },
          TransitGatewayRouteTableId: { Ref: 'TestRouteTable1' }
        },
        LogicalId: 'TestAssociation1'
      };

      const association2: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTableAssociation',
        Properties: {
          TransitGatewayAttachmentId: { Ref: 'TestVpcAttachment2' },
          TransitGatewayRouteTableId: { Ref: 'TestRouteTable2' }
        },
        LogicalId: 'TestAssociation2'
      };

      // Act
      const result = rule.evaluate(transitGateway, stackName, [
        transitGateway, 
        routeTable1, 
        routeTable2, 
        vpcAttachment1, 
        vpcAttachment2,
        association1,
        association2
      ]);

      // Assert
      expect(result).toBeNull();
    });

    it('should return a finding if a route table has an overly permissive route', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway',
          DefaultRouteTableAssociation: 'disable',
          DefaultRouteTablePropagation: 'disable'
        },
        LogicalId: 'TestTransitGateway'
      };

      const routeTable: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' }
        },
        LogicalId: 'TestRouteTable'
      };

      const route: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRoute',
        Properties: {
          TransitGatewayRouteTableId: { Ref: 'TestRouteTable' },
          DestinationCidrBlock: '0.0.0.0/0',
          TransitGatewayAttachmentId: { Ref: 'TestAttachment' }
        },
        LogicalId: 'TestRoute'
      };

      // Act
      const result = rule.evaluate(routeTable, stackName, [transitGateway, routeTable, route]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::TransitGatewayRouteTable');
      expect(result?.resourceName).toBe('TestRouteTable');
      expect(result?.issue).toContain('contains an overly permissive route (0.0.0.0/0)');
    });

    it('should handle different types of Transit Gateway references', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway',
          DefaultRouteTableAssociation: 'disable',
          DefaultRouteTablePropagation: 'disable'
        },
        LogicalId: 'TestTransitGateway'
      };

      // Direct string reference
      const routeTable1: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: 'TestTransitGateway'
        },
        LogicalId: 'TestRouteTable1'
      };

      // Ref reference
      const routeTable2: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' }
        },
        LogicalId: 'TestRouteTable2'
      };

      // GetAtt reference
      const routeTable3: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: { 'Fn::GetAtt': ['TestTransitGateway', 'Id'] }
        },
        LogicalId: 'TestRouteTable3'
      };

      const vpcAttachment1: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayAttachment',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' },
          VpcId: { Ref: 'TestVpc1' }
        },
        LogicalId: 'TestVpcAttachment1'
      };

      const vpcAttachment2: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayAttachment',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' },
          VpcId: { Ref: 'TestVpc2' }
        },
        LogicalId: 'TestVpcAttachment2'
      };

      const association1: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTableAssociation',
        Properties: {
          TransitGatewayAttachmentId: { Ref: 'TestVpcAttachment1' },
          TransitGatewayRouteTableId: { Ref: 'TestRouteTable1' }
        },
        LogicalId: 'TestAssociation1'
      };

      const association2: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTableAssociation',
        Properties: {
          TransitGatewayAttachmentId: { Ref: 'TestVpcAttachment2' },
          TransitGatewayRouteTableId: { Ref: 'TestRouteTable2' }
        },
        LogicalId: 'TestAssociation2'
      };

      // Act
      const result = rule.evaluate(transitGateway, stackName, [
        transitGateway, 
        routeTable1, 
        routeTable2, 
        routeTable3,
        vpcAttachment1, 
        vpcAttachment2,
        association1,
        association2
      ]);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle CDK-generated complex references', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway',
          DefaultRouteTableAssociation: 'disable',
          DefaultRouteTablePropagation: 'disable'
        },
        LogicalId: 'TestTransitGateway'
      };

      // Fn::Sub reference
      const routeTable1: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: { 'Fn::Sub': '${TestTransitGateway}' }
        },
        LogicalId: 'TestRouteTable1'
      };

      // Fn::Sub with variables map
      const routeTable2: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: { 
            'Fn::Sub': [
              '${TgwId}', 
              { 'TgwId': { Ref: 'TestTransitGateway' } }
            ]
          }
        },
        LogicalId: 'TestRouteTable2'
      };

      // Nested Fn::Join with references
      const routeTable3: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: {
            'Fn::Join': [
              '',
              [
                { Ref: 'TestTransitGateway' },
                '-suffix'
              ]
            ]
          }
        },
        LogicalId: 'TestRouteTable3'
      };

      // CDK-style nested token reference
      const routeTable4: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: {
            'Fn::GetAtt': [
              'TestTransitGateway12345', // CDK often adds suffixes to logical IDs
              'Id'
            ]
          }
        },
        LogicalId: 'TestRouteTable4'
      };

      // Deep nested reference structure (common in CDK)
      const routeTable5: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTable',
        Properties: {
          TransitGatewayId: {
            'Fn::If': [
              'UseExistingTgw',
              { Ref: 'ExistingTgwParam' },
              { 
                'Fn::GetAtt': [
                  'TestTransitGateway',
                  'Id'
                ]
              }
            ]
          }
        },
        LogicalId: 'TestRouteTable5'
      };

      const vpcAttachment1: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayAttachment',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' },
          VpcId: { Ref: 'TestVpc1' }
        },
        LogicalId: 'TestVpcAttachment1'
      };

      const vpcAttachment2: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayAttachment',
        Properties: {
          TransitGatewayId: { Ref: 'TestTransitGateway' },
          VpcId: { Ref: 'TestVpc2' }
        },
        LogicalId: 'TestVpcAttachment2'
      };

      const association1: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTableAssociation',
        Properties: {
          TransitGatewayAttachmentId: { Ref: 'TestVpcAttachment1' },
          TransitGatewayRouteTableId: { Ref: 'TestRouteTable1' }
        },
        LogicalId: 'TestAssociation1'
      };

      const association2: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGatewayRouteTableAssociation',
        Properties: {
          TransitGatewayAttachmentId: { Ref: 'TestVpcAttachment2' },
          TransitGatewayRouteTableId: { Ref: 'TestRouteTable2' }
        },
        LogicalId: 'TestAssociation2'
      };

      // Act
      const result = rule.evaluate(transitGateway, stackName, [
        transitGateway, 
        routeTable1, 
        routeTable2, 
        routeTable3,
        routeTable4,
        routeTable5,
        vpcAttachment1, 
        vpcAttachment2,
        association1,
        association2
      ]);

      // Assert
      expect(result).toBeNull();
    });
  });
});
