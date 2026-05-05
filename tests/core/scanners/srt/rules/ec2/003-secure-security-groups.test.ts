import { describe, it, expect } from 'vitest';
import { EC2003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ec2/003-secure-security-groups.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EC2003Rule - Secure Security Groups Tests', () => {
  const rule = new EC2003Rule();
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

  // Helper function to create Security Group Ingress test resources
  function createSecurityGroupIngressResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::SecurityGroupIngress',
      Properties: {
        GroupId: 'sg-12345678',
        IpProtocol: 'tcp',
        FromPort: 80,
        ToPort: 80,
        ...props
      },
      LogicalId: props.LogicalId || 'TestSecurityGroupIngress'
    };
  }

  describe('Security Group Tests', () => {
    it('should detect security group with 0.0.0.0/0 ingress rule', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 80,
            ToPort: 80,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted inbound access from 0.0.0.0/0');
    });

    it('should detect security group with ::/0 ingress rule', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 80,
            ToPort: 80,
            CidrIpv6: '::/0'
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted inbound access from 0.0.0.0/0');
    });

    it('should accept security group with specific CIDR range', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupIngress: [
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

    it('should accept security group with no ingress rules', () => {
      const resource = createSecurityGroupResource({
        // No SecurityGroupIngress
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept security group with empty ingress rules', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupIngress: []
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should skip SSH (port 22) and RDP (port 3389) checks as they are covered by Checkov', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIp: '0.0.0.0/0'
          },
          {
            IpProtocol: 'tcp',
            FromPort: 3389,
            ToPort: 3389,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Should skip these as they're covered by Checkov
    });
  });

  describe('Security Group Ingress Tests', () => {
    it('should detect security group ingress with 0.0.0.0/0', () => {
      const resource = createSecurityGroupIngressResource({
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted inbound access from 0.0.0.0/0');
    });

    it('should detect security group ingress with ::/0', () => {
      const resource = createSecurityGroupIngressResource({
        CidrIpv6: '::/0'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted inbound access from 0.0.0.0/0');
    });

    it('should accept security group ingress with specific CIDR range', () => {
      const resource = createSecurityGroupIngressResource({
        CidrIp: '192.168.1.0/24'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should skip SSH (port 22) and RDP (port 3389) checks as they are covered by Checkov', () => {
      const sshResource = createSecurityGroupIngressResource({
        FromPort: 22,
        ToPort: 22,
        CidrIp: '0.0.0.0/0'
      });

      const rdpResource = createSecurityGroupIngressResource({
        FromPort: 3389,
        ToPort: 3389,
        CidrIp: '0.0.0.0/0'
      });

      const sshResult = rule.evaluate(sshResource, stackName);
      const rdpResult = rule.evaluate(rdpResource, stackName);

      expect(sshResult).toBeNull(); // Should skip SSH as it's covered by Checkov
      expect(rdpResult).toBeNull(); // Should skip RDP as it's covered by Checkov
    });
  });

  describe('CloudFormation Integration Tests', () => {
    it('should handle CloudFormation intrinsic functions in CidrIp', () => {
      const resource = createSecurityGroupIngressResource({
        CidrIp: { 'Ref': 'AllowedCidrIp' }
      });

      // The rule now flags intrinsic functions as potential issues
      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted inbound access');
    });

    it('should detect suspicious parameter names in Ref', () => {
      const resource = createSecurityGroupIngressResource({
        CidrIp: { 'Ref': 'AllowAllIps' }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted inbound access from 0.0.0.0/0');
    });

    it('should handle Fn::Join with 0.0.0.0/0', () => {
      const resource = createSecurityGroupIngressResource({
        CidrIp: { 
          'Fn::Join': ['', ['0.0.0.0', '/0']]
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted inbound access from 0.0.0.0/0');
    });

    it('should handle Fn::Sub with 0.0.0.0/0', () => {
      const resource = createSecurityGroupIngressResource({
        CidrIp: { 
          'Fn::Sub': '0.0.0.0/0'
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted inbound access from 0.0.0.0/0');
    });

    it('should handle Fn::Sub with variable that does not contain 0.0.0.0/0', () => {
      const resource = createSecurityGroupIngressResource({
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
      const resource = createSecurityGroupIngressResource({
        CidrBlock: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted inbound access from 0.0.0.0/0');
    });

    it('should detect Ipv6CidrBlock with ::/0', () => {
      const resource = createSecurityGroupIngressResource({
        Ipv6CidrBlock: '::/0'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Security group allows unrestricted inbound access from 0.0.0.0/0');
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
      expect(result).toBeNull();
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

    it('should handle missing SecurityGroupIngress in security group', () => {
      const resource = createSecurityGroupResource({
        // No SecurityGroupIngress
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle missing CidrIp and CidrIpv6 in security group ingress', () => {
      const resource = createSecurityGroupIngressResource({
        // No CidrIp or CidrIpv6
        SourceSecurityGroupId: 'sg-87654321'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});
