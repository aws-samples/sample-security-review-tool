import { describe, it, expect } from 'vitest';
import { Neptune005Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/neptune/005-restrict-ingress.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Neptune005Rule', () => {
  const rule = new Neptune005Rule();
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

  // Helper function to create Security Group test resources
  function createSecurityGroupResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::SecurityGroup',
      Properties: {
        GroupDescription: 'Test Security Group',
        ...props
      },
      LogicalId: props.LogicalId || 'TestSecurityGroup'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('NEPTUNE-005');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to Neptune DBCluster resources only', () => {
      expect(rule.appliesTo('AWS::Neptune::DBCluster')).toBe(true);
      expect(rule.appliesTo('AWS::Neptune::DBInstance')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Neptune DBCluster Tests', () => {
    it('should fail when VpcSecurityGroupIds is missing', () => {
      // Arrange
      const resource = createNeptuneClusterResource();

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune database security group allows unrestricted ingress from 0.0.0.0/0');
      expect(result?.fix).toContain('Specify explicit VpcSecurityGroupIds');
    });

    it('should fail when VpcSecurityGroupIds is an empty array', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        VpcSecurityGroupIds: []
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune database security group allows unrestricted ingress from 0.0.0.0/0');
      expect(result?.fix).toContain('Add security group IDs to VpcSecurityGroupIds array');
    });

    it('should fail when VpcSecurityGroupIds is a CloudFormation intrinsic function', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        VpcSecurityGroupIds: { Ref: 'SecurityGroupsParameter' }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune database security group allows unrestricted ingress from 0.0.0.0/0');
      expect(result?.fix).toContain('Use explicit security group arrays');
    });

    it('should fail when VpcSecurityGroupIds references security groups that allow 0.0.0.0/0', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'OpenSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 8182,
            ToPort: 8182,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const resource = createNeptuneClusterResource({
        VpcSecurityGroupIds: ['OpenSecurityGroup']
      });

      const allResources = [resource, securityGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune database security group allows unrestricted ingress from 0.0.0.0/0');
      expect(result?.fix).toContain('Remove ingress rules allowing 0.0.0.0/0');
    });

    it('should pass when VpcSecurityGroupIds references security groups that properly restrict access', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'RestrictedSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 8182,
            ToPort: 8182,
            CidrIp: '10.0.0.0/16'
          }
        ]
      });

      const resource = createNeptuneClusterResource({
        VpcSecurityGroupIds: ['RestrictedSecurityGroup']
      });

      const allResources = [resource, securityGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should fail when VpcSecurityGroupIds references external security groups', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        VpcSecurityGroupIds: ['sg-12345678']
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune database security group allows unrestricted ingress from 0.0.0.0/0');
      expect(result?.fix).toContain('Ensure external security group');
    });
  });

  describe('Security Group Resolution Tests', () => {
    it('should resolve security group references via Ref', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'RefSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 8182,
            ToPort: 8182,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const resource = createNeptuneClusterResource({
        VpcSecurityGroupIds: [{ Ref: 'RefSecurityGroup' }]
      });

      const allResources = [resource, securityGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune database security group allows unrestricted ingress from 0.0.0.0/0');
      expect(result?.fix).toContain('Remove ingress rules allowing 0.0.0.0/0');
    });

    it('should resolve security group references via GetAtt', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'GetAttSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 8182,
            ToPort: 8182,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const resource = createNeptuneClusterResource({
        VpcSecurityGroupIds: [{ 'Fn::GetAtt': ['GetAttSecurityGroup', 'GroupId'] }]
      });

      const allResources = [resource, securityGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune database security group allows unrestricted ingress from 0.0.0.0/0');
      expect(result?.fix).toContain('Remove ingress rules allowing 0.0.0.0/0');
    });

    it('should handle unresolvable security group references', () => {
      // Arrange
      const resource = createNeptuneClusterResource({
        VpcSecurityGroupIds: [{ 'Fn::ImportValue': 'ExportedSecurityGroup' }]
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune database security group allows unrestricted ingress from 0.0.0.0/0');
      expect(result?.fix).toContain('Use explicit security group IDs');
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
      expect(result?.issue).toContain('Neptune database security group allows unrestricted ingress from 0.0.0.0/0');
    });

    it('should handle security groups with IPv6 unrestricted access', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'IPv6OpenSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 8182,
            ToPort: 8182,
            CidrIpv6: '::/0'
          }
        ]
      });

      const resource = createNeptuneClusterResource({
        VpcSecurityGroupIds: ['IPv6OpenSecurityGroup']
      });

      const allResources = [resource, securityGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Neptune::DBCluster');
      expect(result?.resourceName).toBe('TestNeptuneCluster');
      expect(result?.issue).toContain('Neptune database security group allows unrestricted ingress from 0.0.0.0/0');
    });

    it('should handle security groups with intrinsic functions in CIDR', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'IntrinsicCidrSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 8182,
            ToPort: 8182,
            CidrIp: { Ref: 'AllowedCidr' }
          }
        ]
      });

      const resource = createNeptuneClusterResource({
        VpcSecurityGroupIds: ['IntrinsicCidrSecurityGroup']
      });

      const allResources = [resource, securityGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      // The rule skips intrinsic functions in CIDR and relies on the parent check to flag them
      // Since we're providing a valid security group reference, it should pass
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

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });
});
