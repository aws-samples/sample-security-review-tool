import { describe, it, expect } from 'vitest';
import { ESH003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/opensearch/003-security-group-restrictions.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ESH003Rule', () => {
  const rule = new ESH003Rule();
  const stackName = 'test-stack';

  // Helper functions to create test resources
  function createOpenSearchResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::OpenSearchService::Domain',
      Properties: {
        DomainName: 'test-domain',
        EngineVersion: 'OpenSearch_1.0',
        ClusterConfig: {
          InstanceType: 't3.small.search',
          InstanceCount: 2
        },
        ...props
      },
      LogicalId: props.LogicalId || 'TestOpenSearchDomain'
    };
  }

  function createSecurityGroupResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::SecurityGroup',
      Properties: {
        GroupDescription: 'Test Security Group',
        VpcId: 'vpc-12345',
        ...props
      },
      LogicalId: props.LogicalId || 'TestSecurityGroup'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('ESH-003');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to the correct resource types', () => {
      expect(rule.appliesTo('AWS::OpenSearchService::Domain')).toBe(true);
      expect(rule.appliesTo('AWS::Elasticsearch::Domain')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('OpenSearch Domain Tests', () => {
    it('should detect missing VPC Options', () => {
      // Arrange
      const domain = createOpenSearchResource();
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('OpenSearch security group allows unrestricted access');
    });

    it('should detect missing SecurityGroupIds in VPC Options', () => {
      // Arrange
      const domain = createOpenSearchResource({
        VPCOptions: {
          SubnetIds: ['subnet-123', 'subnet-456']
        }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('OpenSearch security group allows unrestricted access');
    });

    it('should detect overly permissive security groups', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'OpenSearchSG',
        SecurityGroupIngress: [{
          IpProtocol: 'tcp',
          FromPort: 443,
          ToPort: 443,
          CidrIp: '0.0.0.0/0'
        }]
      });
      
      const domain = createOpenSearchResource({
        LogicalId: 'OpenSearchDomain',
        VPCOptions: {
          SubnetIds: ['subnet-123', 'subnet-456'],
          SecurityGroupIds: ['OpenSearchSG']
        }
      });
      
      const allResources = [domain, securityGroup];
      
      // Act
      const result = rule.evaluate(domain, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('OpenSearch security group allows unrestricted access');
    });

    it('should pass with properly restricted security groups', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'OpenSearchSG',
        SecurityGroupIngress: [{
          IpProtocol: 'tcp',
          FromPort: 443,
          ToPort: 443,
          CidrIp: '10.0.0.0/16'
        }]
      });
      
      const domain = createOpenSearchResource({
        VPCOptions: {
          SubnetIds: ['subnet-123', 'subnet-456'],
          SecurityGroupIds: ['OpenSearchSG']
        }
      });
      
      const allResources = [domain, securityGroup];
      
      // Act
      const result = rule.evaluate(domain, stackName, allResources);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should handle security group references using Ref', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'OpenSearchSG',
        SecurityGroupIngress: [{
          IpProtocol: 'tcp',
          FromPort: 443,
          ToPort: 443,
          CidrIp: '10.0.0.0/16'
        }]
      });
      
      const domain = createOpenSearchResource({
        VPCOptions: {
          SubnetIds: ['subnet-123', 'subnet-456'],
          SecurityGroupIds: [{ Ref: 'OpenSearchSG' }]
        }
      });
      
      const allResources = [domain, securityGroup];
      
      // Act
      const result = rule.evaluate(domain, stackName, allResources);
      
      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties in resource', () => {
      // Arrange
      const domain = {
        Type: 'AWS::OpenSearchService::Domain',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull(); // Should detect missing VPCOptions
    });

    it('should handle empty SecurityGroupIds array', () => {
      // Arrange
      const domain = createOpenSearchResource({
        VPCOptions: {
          SubnetIds: ['subnet-123', 'subnet-456'],
          SecurityGroupIds: []
        }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).toBeNull(); // Empty array is handled as no security groups
    });

    it('should handle security groups not found in the template', () => {
      // Arrange
      const domain = createOpenSearchResource({
        VPCOptions: {
          SubnetIds: ['subnet-123', 'subnet-456'],
          SecurityGroupIds: ['NonexistentSG']
        }
      });
      
      const allResources = [domain];
      
      // Act
      const result = rule.evaluate(domain, stackName, allResources);
      
      // Assert
      expect(result).toBeNull(); // Cannot evaluate missing SGs, so shouldn't fail
    });
  });
});
