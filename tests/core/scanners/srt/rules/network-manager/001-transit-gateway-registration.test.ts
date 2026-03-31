import { describe, it, expect } from 'vitest';
import { NEM001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/network-manager/001-transit-gateway-registration.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('NEM001Rule', () => {
  const rule = new NEM001Rule();
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

    it('should return null if the resource is not a Transit Gateway or Global Network related resource', () => {
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

    it('should return a finding if Transit Gateway exists but no Global Network is defined', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway'
        },
        LogicalId: 'TestTransitGateway'
      };

      // Act
      const result = rule.evaluate(transitGateway, stackName, [transitGateway]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::TransitGateway');
      expect(result?.resourceName).toBe('TestTransitGateway');
      expect(result?.issue).toContain('No AWS Network Manager Global Network found');
    });

    it('should return a finding if Transit Gateway exists with Global Network but no registration', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway'
        },
        LogicalId: 'TestTransitGateway'
      };

      const globalNetwork: CloudFormationResource = {
        Type: 'AWS::NetworkManager::GlobalNetwork',
        Properties: {
          Description: 'Test Global Network'
        },
        LogicalId: 'TestGlobalNetwork'
      };

      // Act
      const result = rule.evaluate(transitGateway, stackName, [transitGateway, globalNetwork]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::TransitGateway');
      expect(result?.resourceName).toBe('TestTransitGateway');
      expect(result?.issue).toContain('is not registered with AWS Network Manager');
    });

    it('should return a finding if Global Network exists but not all Transit Gateways are registered', () => {
      // Arrange
      const transitGateway1: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway 1'
        },
        LogicalId: 'TestTransitGateway1'
      };

      const transitGateway2: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway 2'
        },
        LogicalId: 'TestTransitGateway2'
      };

      const globalNetwork: CloudFormationResource = {
        Type: 'AWS::NetworkManager::GlobalNetwork',
        Properties: {
          Description: 'Test Global Network'
        },
        LogicalId: 'TestGlobalNetwork'
      };

      const registration: CloudFormationResource = {
        Type: 'AWS::NetworkManager::TransitGatewayRegistration',
        Properties: {
          GlobalNetworkId: { Ref: 'TestGlobalNetwork' },
          TransitGatewayArn: { Ref: 'TestTransitGateway1' }
        },
        LogicalId: 'TestRegistration'
      };

      // Act
      const result = rule.evaluate(globalNetwork, stackName, [transitGateway1, transitGateway2, globalNetwork, registration]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::NetworkManager::GlobalNetwork');
      expect(result?.resourceName).toBe('TestGlobalNetwork');
      expect(result?.issue).toContain('Not all Transit Gateways are registered');
    });

    it('should return null if all Transit Gateways are registered with Network Manager', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway'
        },
        LogicalId: 'TestTransitGateway'
      };

      const globalNetwork: CloudFormationResource = {
        Type: 'AWS::NetworkManager::GlobalNetwork',
        Properties: {
          Description: 'Test Global Network'
        },
        LogicalId: 'TestGlobalNetwork'
      };

      const registration: CloudFormationResource = {
        Type: 'AWS::NetworkManager::TransitGatewayRegistration',
        Properties: {
          GlobalNetworkId: { Ref: 'TestGlobalNetwork' },
          TransitGatewayArn: { Ref: 'TestTransitGateway' }
        },
        LogicalId: 'TestRegistration'
      };

      // Act
      const result = rule.evaluate(transitGateway, stackName, [transitGateway, globalNetwork, registration]);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle different types of references for Transit Gateway and Global Network', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway'
        },
        LogicalId: 'TestTransitGateway'
      };

      const globalNetwork: CloudFormationResource = {
        Type: 'AWS::NetworkManager::GlobalNetwork',
        Properties: {
          Description: 'Test Global Network'
        },
        LogicalId: 'TestGlobalNetwork'
      };

      // Using Fn::GetAtt for Transit Gateway reference
      const registration1: CloudFormationResource = {
        Type: 'AWS::NetworkManager::TransitGatewayRegistration',
        Properties: {
          GlobalNetworkId: { Ref: 'TestGlobalNetwork' },
          TransitGatewayArn: { 'Fn::GetAtt': ['TestTransitGateway', 'Id'] }
        },
        LogicalId: 'TestRegistration1'
      };

      // Act
      const result = rule.evaluate(transitGateway, stackName, [transitGateway, globalNetwork, registration1]);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle CDK-generated complex references', () => {
      // Arrange
      const transitGateway: CloudFormationResource = {
        Type: 'AWS::EC2::TransitGateway',
        Properties: {
          Description: 'Test Transit Gateway'
        },
        LogicalId: 'TestTransitGateway'
      };

      const globalNetwork: CloudFormationResource = {
        Type: 'AWS::NetworkManager::GlobalNetwork',
        Properties: {
          Description: 'Test Global Network'
        },
        LogicalId: 'TestGlobalNetwork'
      };

      // Using Fn::Sub for Global Network reference
      const registration: CloudFormationResource = {
        Type: 'AWS::NetworkManager::TransitGatewayRegistration',
        Properties: {
          GlobalNetworkId: { 'Fn::Sub': '${TestGlobalNetwork}' },
          TransitGatewayArn: { 
            'Fn::Join': [
              '',
              [
                'arn:aws:ec2:',
                { Ref: 'AWS::Region' },
                ':',
                { Ref: 'AWS::AccountId' },
                ':transit-gateway/',
                { Ref: 'TestTransitGateway' }
              ]
            ]
          }
        },
        LogicalId: 'TestRegistration'
      };

      // Act
      const result = rule.evaluate(transitGateway, stackName, [transitGateway, globalNetwork, registration]);

      // Assert
      expect(result).toBeNull();
    });
  });
});
