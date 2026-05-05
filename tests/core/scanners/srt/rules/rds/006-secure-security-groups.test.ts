import { describe, it, expect } from 'vitest';
import { Rds006Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/rds/006-secure-security-groups.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Rds006Rule', () => {
  const rule = new Rds006Rule();
  const stackName = 'test-stack';

  // Helper function to create SecurityGroup test resources
  function createSecurityGroupResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::SecurityGroup',
      Properties: {
        GroupDescription: 'Test Security Group',
        VpcId: { Ref: 'TestVPC' },
        ...props
      },
      LogicalId: props.LogicalId || 'TestSecurityGroup'
    };
  }

  // Helper function to create SecurityGroupIngress test resources
  function createSecurityGroupIngressResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::SecurityGroupIngress',
      Properties: {
        GroupId: { Ref: 'TestSecurityGroup' },
        IpProtocol: 'tcp',
        FromPort: 3306,
        ToPort: 3306,
        ...props
      },
      LogicalId: props.LogicalId || 'TestSecurityGroupIngress'
    };
  }

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
          { Ref: 'Subnet1' },
          { Ref: 'Subnet2' }
        ],
        ...props
      },
      LogicalId: props.LogicalId || 'TestDbSubnetGroup'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('RDS-006');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to security group and security group ingress resources', () => {
      expect(rule.appliesTo('AWS::EC2::SecurityGroup')).toBe(true);
      expect(rule.appliesTo('AWS::EC2::SecurityGroupIngress')).toBe(true);
      expect(rule.appliesTo('AWS::RDS::DBInstance')).toBe(false);
    });
  });

  describe('Security Group Tests', () => {
    it('should detect security group with public ingress rules associated with RDS', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'TestSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::SecurityGroup');
      expect(result?.resourceName).toBe('TestSecurityGroup');
      expect(result?.issue).toContain('RDS security group allows access from 0.0.0.0/0 on port 3306');
    });

    it('should detect security group with public IPv6 ingress rules associated with RDS', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIpv6: '::/0'
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'TestSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::SecurityGroup');
      expect(result?.resourceName).toBe('TestSecurityGroup');
      expect(result?.issue).toContain('RDS security group allows access from 0.0.0.0/0 on port 3306');
    });

    it('should not flag security group with private ingress rules associated with RDS', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: '10.0.0.0/16'
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'TestSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should not flag security group with public ingress rules NOT associated with RDS', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'OtherSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle multiple ingress rules and only flag public ones', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: '10.0.0.0/16'
          },
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'TestSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::SecurityGroup');
      expect(result?.resourceName).toBe('TestSecurityGroup');
      expect(result?.issue).toContain('RDS security group allows access from 0.0.0.0/0 on port 3306');
    });
  });

  describe('Security Group Ingress Tests', () => {
    it('should detect standalone ingress rule with public access for RDS security group', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'RdsSecurityGroup'
      });

      const securityGroupIngress = createSecurityGroupIngressResource({
        GroupId: 'RdsSecurityGroup',
        CidrIp: '0.0.0.0/0'
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'RdsSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, securityGroupIngress, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroupIngress, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::SecurityGroupIngress');
      expect(result?.resourceName).toBe('TestSecurityGroupIngress');
      expect(result?.issue).toContain('RDS security group allows access from 0.0.0.0/0 on port 3306');
    });

    it('should not flag standalone ingress rule with private access for RDS security group', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'RdsSecurityGroup'
      });

      const securityGroupIngress = createSecurityGroupIngressResource({
        GroupId: 'RdsSecurityGroup',
        CidrIp: '10.0.0.0/16'
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'RdsSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, securityGroupIngress, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroupIngress, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should not flag standalone ingress rule with public access for non-RDS security group', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'NonRdsSecurityGroup'
      });

      const securityGroupIngress = createSecurityGroupIngressResource({
        GroupId: 'NonRdsSecurityGroup',
        CidrIp: '0.0.0.0/0'
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'OtherSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, securityGroupIngress, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroupIngress, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('RDS Association Tests', () => {
    it('should detect security group associated with RDS via VPCSecurityGroups', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'TestSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::SecurityGroup');
      expect(result?.resourceName).toBe('TestSecurityGroup');
    });

    it('should detect security group associated with RDS via GetAtt reference', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { 'Fn::GetAtt': ['TestSecurityGroup', 'GroupId'] }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::SecurityGroup');
      expect(result?.resourceName).toBe('TestSecurityGroup');
    });

    it('should detect security group associated with RDS cluster', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const rdsCluster = createRdsClusterResource({
        VPCSecurityGroups: [
          { Ref: 'TestSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, rdsCluster];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::SecurityGroup');
      expect(result?.resourceName).toBe('TestSecurityGroup');
    });

    it('should detect security group associated with RDS via DBSubnetGroup', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const subnetGroup = createDbSubnetGroupResource({
        Tags: [
          {
            Key: 'SecurityGroup',
            Value: { Ref: 'TestSecurityGroup' }
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        DBSubnetGroupName: { Ref: 'TestDbSubnetGroup' }
      });

      const allResources = [securityGroup, subnetGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::SecurityGroup');
      expect(result?.resourceName).toBe('TestSecurityGroup');
    });
  });

  describe('CloudFormation Intrinsic Function Tests', () => {
    it('should handle Ref in CIDR values', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: { Ref: 'AllowedCidr' }
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'TestSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).toBeNull(); // Should pass because we can't validate dynamic values
    });

    it('should handle Fn::If in CIDR values', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: { 
              'Fn::If': [
                'UsePublicAccess',
                '0.0.0.0/0',
                '10.0.0.0/16'
              ]
            }
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'TestSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EC2::SecurityGroup');
      expect(result?.resourceName).toBe('TestSecurityGroup');
      expect(result?.issue).toContain('RDS security group allows access from 0.0.0.0/0');
    });

    it('should handle Fn::Join in CIDR values', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: { 
              'Fn::Join': [
                '', 
                ['0.0.0.0', '/0']
              ]
            }
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'TestSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).toBeNull(); // Should pass because we can't validate dynamic values
    });
  });

  describe('Port Description Tests', () => {
    it('should correctly describe single port', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'TestSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('on port 3306');
    });

    it('should correctly describe port range', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3307,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'TestSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('on port 3306-3307');
    });

    it('should correctly describe missing port range as all ports', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'TestSecurityGroup' }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('on port all ports');
    });
  });

  describe('Edge Cases', () => {
    it('should return null if allResources is not provided', () => {
      // Arrange
      const securityGroup = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 3306,
            ToPort: 3306,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      // Act
      const result = rule.evaluate(securityGroup, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle missing Properties', () => {
      // Arrange
      const securityGroup = {
        Type: 'AWS::EC2::SecurityGroup',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      const rdsInstance = createRdsInstanceResource({
        VPCSecurityGroups: [
          { Ref: 'MissingProperties' }
        ]
      });

      const allResources = [securityGroup, rdsInstance];

      // Act
      const result = rule.evaluate(securityGroup, stackName, allResources);

      // Assert
      expect(result).toBeNull(); // Should pass because there's no SecurityGroupIngress to check
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
  });
});
