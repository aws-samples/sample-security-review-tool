import { describe, it, expect } from 'vitest';
import { DMS002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/dms/002-security-group-least-privilege.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('DMS-002: Restrict DMS replication instance security groups by least privilege', () => {
  const rule = new DMS002Rule();
  const stackName = 'test-stack';

  it('should flag DMS instance with overly permissive security group', () => {
    const dmsInstance: CloudFormationResource = {
      Type: 'AWS::DMS::ReplicationInstance',
      LogicalId: 'TestDMSInstance',
      Properties: {
        ReplicationInstanceClass: 'dms.t2.small',
        VpcSecurityGroupIds: ['TestSecurityGroup']
      }
    };

    const securityGroup: CloudFormationResource = {
      Type: 'AWS::EC2::SecurityGroup',
      LogicalId: 'TestSecurityGroup',
      Properties: {
        SecurityGroupIngress: [{
          IpProtocol: '-1',
          CidrIp: '0.0.0.0/0'
        }]
      }
    };

    const allResources = [dmsInstance, securityGroup];
    const result = rule.evaluate(dmsInstance, stackName, allResources);
    
    expect(result).not.toBeNull();
    expect(result?.resourceType).toBe('AWS::DMS::ReplicationInstance');
    expect(result?.fix).toBe('Restrict security group rules to specific ports, protocols, and CIDR blocks required for DMS operations.');
  });

  it('should flag security group with all ports open', () => {
    const dmsInstance: CloudFormationResource = {
      Type: 'AWS::DMS::ReplicationInstance',
      LogicalId: 'TestDMSInstance',
      Properties: {
        VpcSecurityGroupIds: ['TestSecurityGroup']
      }
    };

    const securityGroup: CloudFormationResource = {
      Type: 'AWS::EC2::SecurityGroup',
      LogicalId: 'TestSecurityGroup',
      Properties: {
        SecurityGroupIngress: [{
          IpProtocol: 'tcp',
          FromPort: 0,
          ToPort: 65535,
          CidrIp: '10.0.0.0/16'
        }]
      }
    };

    const allResources = [dmsInstance, securityGroup];
    const result = rule.evaluate(securityGroup, stackName, allResources);
    
    expect(result).not.toBeNull();
    expect(result?.resourceType).toBe('AWS::EC2::SecurityGroup');
  });

  it('should flag security group with 0.0.0.0/0 on ingress', () => {
    const dmsInstance: CloudFormationResource = {
      Type: 'AWS::DMS::ReplicationInstance',
      LogicalId: 'TestDMSInstance',
      Properties: {
        VpcSecurityGroupIds: ['TestSecurityGroup']
      }
    };

    const securityGroup: CloudFormationResource = {
      Type: 'AWS::EC2::SecurityGroup',
      LogicalId: 'TestSecurityGroup',
      Properties: {
        SecurityGroupIngress: [{
          IpProtocol: 'tcp',
          FromPort: 3306,
          ToPort: 3306,
          CidrIp: '0.0.0.0/0' // Exposes instance to internet
        }]
      }
    };

    const allResources = [dmsInstance, securityGroup];
    const result = rule.evaluate(securityGroup, stackName, allResources);
    
    expect(result).not.toBeNull();
  });

  it('should flag egress 0.0.0.0/0 with all protocols/ports', () => {
    const dmsInstance: CloudFormationResource = {
      Type: 'AWS::DMS::ReplicationInstance',
      LogicalId: 'TestDMSInstance',
      Properties: {
        VpcSecurityGroupIds: ['TestSecurityGroup']
      }
    };

    const securityGroup: CloudFormationResource = {
      Type: 'AWS::EC2::SecurityGroup',
      LogicalId: 'TestSecurityGroup',
      Properties: {
        SecurityGroupEgress: [{
          IpProtocol: '-1', // All protocols
          CidrIp: '0.0.0.0/0' // DMS shouldn't need arbitrary outbound
        }]
      }
    };

    const allResources = [dmsInstance, securityGroup];
    const result = rule.evaluate(securityGroup, stackName, allResources);
    
    expect(result).not.toBeNull();
  });

  it('should pass compliant security group with specific CIDR and ports', () => {
    const dmsInstance: CloudFormationResource = {
      Type: 'AWS::DMS::ReplicationInstance',
      LogicalId: 'TestDMSInstance',
      Properties: {
        VpcSecurityGroupIds: ['TestSecurityGroup']
      }
    };

    const securityGroup: CloudFormationResource = {
      Type: 'AWS::EC2::SecurityGroup',
      LogicalId: 'TestSecurityGroup',
      Properties: {
        SecurityGroupIngress: [{
          IpProtocol: 'tcp',
          FromPort: 1433,
          ToPort: 1433,
          CidrIp: '10.0.0.0/16' // Restricted CIDR
        }],
        SecurityGroupEgress: [{
          IpProtocol: 'tcp',
          FromPort: 443,
          ToPort: 443,
          CidrIp: '10.0.0.0/16' // Specific egress
        }]
      }
    };

    const allResources = [dmsInstance, securityGroup];
    const result = rule.evaluate(dmsInstance, stackName, allResources);
    
    expect(result).toBeNull();
  });

  it('should ignore security groups not used by DMS instances', () => {
    const securityGroup: CloudFormationResource = {
      Type: 'AWS::EC2::SecurityGroup',
      LogicalId: 'UnusedSecurityGroup',
      Properties: {
        SecurityGroupIngress: [{
          IpProtocol: '-1',
          CidrIp: '0.0.0.0/0'
        }]
      }
    };

    const result = rule.evaluate(securityGroup, stackName, [securityGroup]);
    expect(result).toBeNull();
  });

  it('should return null for DMS instance without security groups', () => {
    const dmsInstance: CloudFormationResource = {
      Type: 'AWS::DMS::ReplicationInstance',
      LogicalId: 'TestDMSInstance',
      Properties: {
        ReplicationInstanceClass: 'dms.t2.small'
      }
    };

    const result = rule.evaluate(dmsInstance, stackName, [dmsInstance]);
    expect(result).toBeNull();
  });

  it('should ignore non-applicable resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestBucket',
      Properties: {}
    };

    const result = rule.evaluate(resource, stackName, [resource]);
    expect(result).toBeNull();
  });

  it('should have correct rule properties', () => {
    expect(rule.id).toBe('DMS-002');
    expect(rule.priority).toBe('HIGH');
    expect(rule.appliesTo('AWS::DMS::ReplicationInstance')).toBe(true);
    expect(rule.appliesTo('AWS::EC2::SecurityGroup')).toBe(true);
    expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
  });
});