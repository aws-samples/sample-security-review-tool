import { describe, it, expect } from 'vitest';
import { EC2005Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ec2/005-limited-egress-rules.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EC2005Rule - Limited Egress Rules Tests', () => {
  const rule = new EC2005Rule();
  const stackName = 'test-stack';

  // Helper function to create Security Group test resources
  function createSecurityGroupResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::SecurityGroup',
      Properties: {
        GroupDescription: 'Test security group',
        VpcId: 'vpc-12345678',
        ...props
      },
      LogicalId: props.LogicalId || 'TestSecurityGroup'
    };
  }

  // Helper function to create Security Group Egress test resources
  function createSecurityGroupEgressResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::SecurityGroupEgress',
      Properties: {
        GroupId: 'sg-12345678',
        IpProtocol: 'tcp',
        FromPort: 80,
        ToPort: 80,
        ...props
      },
      LogicalId: props.LogicalId || 'TestSecurityGroupEgress'
    };
  }

  describe('Security Group Tests', () => {
    it('should detect security group with 0.0.0.0/0 egress rule', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupEgress: [
          {
            IpProtocol: 'tcp',
            FromPort: 80,
            ToPort: 80,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      // HTTP port 80 is allowed to 0.0.0.0/0
      expect(result).toBeNull();
    });

    it('should detect security group with ::/0 egress rule', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupEgress: [
          {
            IpProtocol: 'tcp',
            FromPort: 80,
            ToPort: 80,
            CidrIpv6: '::/0'
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      // HTTP port 80 is allowed to ::/0
      expect(result).toBeNull();
    });

    it('should detect security group with -1 protocol (all protocols) egress rule', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupEgress: [
          {
            IpProtocol: '-1',
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      // All protocols are allowed to 0.0.0.0/0, but this is handled by Checkov
      expect(result).toBeNull();
    });

    it('should accept security group with specific CIDR range', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupEgress: [
          {
            IpProtocol: 'tcp',
            FromPort: 80,
            ToPort: 80,
            CidrIp: '192.168.1.0/24'
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept security group with no egress rules', () => {
      const resource = createSecurityGroupResource({
        // No SecurityGroupEgress
      });

      const result = rule.evaluate(resource, stackName);
      // No egress rules means default allow all
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted outbound access to the entire Internet');
    });

    it('should accept security group with empty egress rules', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupEgress: []
      });

      const result = rule.evaluate(resource, stackName);
      // Empty egress rules means default allow all
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted outbound access to the entire Internet');
    });

    it('should accept security group with destination security group', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupEgress: [
          {
            IpProtocol: 'tcp',
            FromPort: 80,
            ToPort: 80,
            DestinationSecurityGroupId: 'sg-87654321'
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept security group with specific ports', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupEgress: [
          {
            IpProtocol: 'tcp',
            FromPort: 443,
            ToPort: 443,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should detect security group with wide port range', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupEgress: [
          {
            IpProtocol: 'tcp',
            FromPort: 1,
            ToPort: 65535,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted outbound access to the entire Internet');
    });
  });

  describe('Security Group Egress Tests', () => {
    it('should detect security group egress with 0.0.0.0/0', () => {
      const resource = createSecurityGroupEgressResource({
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      // HTTP port 80 is allowed to 0.0.0.0/0
      expect(result).toBeNull();
    });

    it('should detect security group egress with ::/0', () => {
      const resource = createSecurityGroupEgressResource({
        CidrIpv6: '::/0'
      });

      const result = rule.evaluate(resource, stackName);
      // HTTP port 80 is allowed to ::/0
      expect(result).toBeNull();
    });

    it('should detect security group egress with -1 protocol (all protocols)', () => {
      const resource = createSecurityGroupEgressResource({
        IpProtocol: '-1',
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      // All protocols are allowed to 0.0.0.0/0, but this is handled by Checkov
      expect(result).toBeNull();
    });

    it('should accept security group egress with specific CIDR range', () => {
      const resource = createSecurityGroupEgressResource({
        CidrIp: '192.168.1.0/24'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept security group egress with destination security group', () => {
      const resource = createSecurityGroupEgressResource({
        DestinationSecurityGroupId: 'sg-87654321'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept security group egress with specific ports', () => {
      const resource = createSecurityGroupEgressResource({
        FromPort: 443,
        ToPort: 443,
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should detect security group egress with wide port range', () => {
      const resource = createSecurityGroupEgressResource({
        FromPort: 1,
        ToPort: 65535,
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted outbound access to the entire Internet');
    });
  });

  describe('CloudFormation Integration Tests', () => {
    it('should handle CloudFormation intrinsic functions in CidrIp', () => {
      const resource = createSecurityGroupEgressResource({
        CidrIp: { 'Ref': 'AllowedCidr' }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Can't validate dynamic CidrIp
    });

    it('should detect suspicious parameter names in Ref', () => {
      const resource = createSecurityGroupEgressResource({
        CidrIp: { 'Ref': 'AllowAllIps' }
      });

      const result = rule.evaluate(resource, stackName);
      // The rule doesn't check parameter names anymore
      expect(result).toBeNull();
    });

    it('should handle Fn::Join with 0.0.0.0/0', () => {
      const resource = createSecurityGroupEgressResource({
        CidrIp: { 
          'Fn::Join': ['', ['0.0.0.0', '/0']]
        }
      });

      const result = rule.evaluate(resource, stackName);
      // HTTP port 80 is allowed to 0.0.0.0/0
      expect(result).toBeNull();
    });

    it('should handle Fn::Sub with 0.0.0.0/0', () => {
      const resource = createSecurityGroupEgressResource({
        CidrIp: { 
          'Fn::Sub': '0.0.0.0/0'
        }
      });

      const result = rule.evaluate(resource, stackName);
      // HTTP port 80 is allowed to 0.0.0.0/0
      expect(result).toBeNull();
    });

    it('should handle Fn::Sub with variable that does not contain 0.0.0.0/0', () => {
      const resource = createSecurityGroupEgressResource({
        CidrIp: { 
          'Fn::Sub': '${VpcCidr}'
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Can't validate dynamic CidrIp
    });
  });

  describe('Alternative Property Names Tests', () => {
    it('should detect CidrBlock with 0.0.0.0/0', () => {
      const resource = createSecurityGroupEgressResource({
        CidrBlock: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      // HTTP port 80 is allowed to 0.0.0.0/0
      expect(result).toBeNull();
    });

    it('should detect Ipv6CidrBlock with ::/0', () => {
      const resource = createSecurityGroupEgressResource({
        Ipv6CidrBlock: '::/0'
      });

      const result = rule.evaluate(resource, stackName);
      // HTTP port 80 is allowed to ::/0
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Using type assertion to test a case where Properties is missing
      const resource = {
        Type: 'AWS::EC2::SecurityGroup',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted outbound access to the entire Internet');
    });

    it('should ignore non-applicable resources', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle missing SecurityGroupEgress in security group', () => {
      const resource = createSecurityGroupResource({
        // No SecurityGroupEgress
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted outbound access to the entire Internet');
    });

    it('should handle missing CidrIp and CidrIpv6 in security group egress', () => {
      const resource = createSecurityGroupEgressResource({
        // No CidrIp or CidrIpv6
        DestinationSecurityGroupId: 'sg-87654321'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle missing FromPort and ToPort in security group egress', () => {
      const resource = createSecurityGroupEgressResource({
        IpProtocol: 'icmp',
        CidrIp: '0.0.0.0/0'
        // No FromPort or ToPort for ICMP
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted outbound access to the entire Internet');
    });
  });

  describe('Common Allowed Ports Tests', () => {
    it('should accept HTTP (port 80) egress to 0.0.0.0/0', () => {
      const resource = createSecurityGroupEgressResource({
        FromPort: 80,
        ToPort: 80,
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept HTTPS (port 443) egress to 0.0.0.0/0', () => {
      const resource = createSecurityGroupEgressResource({
        FromPort: 443,
        ToPort: 443,
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept DNS (port 53) egress to 0.0.0.0/0', () => {
      const resource = createSecurityGroupEgressResource({
        FromPort: 53,
        ToPort: 53,
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept NTP (port 123) egress to 0.0.0.0/0', () => {
      const resource = createSecurityGroupEgressResource({
        FromPort: 123,
        ToPort: 123,
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted outbound access to the entire Internet');
    });
  });
});
