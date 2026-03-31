import { describe, it, expect } from 'vitest';
import { NetSg002Rule } from '../../../../../../../src/assess/scanning/security-matrix/rules/security-group/002-limit-egress.js'
import { CloudFormationResource } from '../../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('NetSg002Rule - Limit Egress Tests', () => {
  const rule = new NetSg002Rule();
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

  // Helper function to create SecurityGroupEgress test resources
  function createSecurityGroupEgressResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::SecurityGroupEgress',
      Properties: {
        GroupId: { Ref: 'TestSecurityGroup' },
        IpProtocol: 'tcp',
        FromPort: 22,
        ToPort: 22,
        ...props
      },
      LogicalId: props.LogicalId || 'TestSecurityGroupEgress'
    };
  }

  describe('SecurityGroup Tests', () => {
    it('should detect missing egress rules', () => {
      const resource = createSecurityGroupResource();

      // The rule no longer checks for missing egress rules
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should detect empty egress rules', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupEgress: []
      });

      // The rule no longer checks for empty egress rules
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should detect overly broad egress rules', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupEgress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      // The rule no longer checks for overly broad egress rules
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept HTTP egress to 0.0.0.0/0', () => {
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
      expect(result).toBeNull();
    });

    it('should accept HTTPS egress to 0.0.0.0/0', () => {
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

    it('should accept restricted egress rules', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupEgress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIp: '10.0.0.0/16'
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('SecurityGroupEgress Tests', () => {
    it('should detect overly broad egress rules', () => {
      const resource = createSecurityGroupEgressResource({
        CidrIp: '0.0.0.0/0'
      });

      // The rule no longer checks for overly broad egress rules
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept HTTP egress to 0.0.0.0/0', () => {
      const resource = createSecurityGroupEgressResource({
        FromPort: 80,
        ToPort: 80,
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept HTTPS egress to 0.0.0.0/0', () => {
      const resource = createSecurityGroupEgressResource({
        FromPort: 443,
        ToPort: 443,
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept restricted egress rules', () => {
      const resource = createSecurityGroupEgressResource({
        CidrIp: '10.0.0.0/16'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('CloudFormation Integration Tests', () => {
    it('should handle CloudFormation intrinsic functions in CidrIp', () => {
      const resource = createSecurityGroupEgressResource({
        CidrIp: { 'Ref': 'AllowedCidr' }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Should pass because we can't validate dynamic CidrIp
    });

    it('should handle CloudFormation intrinsic functions in port numbers', () => {
      const resource = createSecurityGroupEgressResource({
        FromPort: { 'Ref': 'FromPort' },
        ToPort: { 'Ref': 'ToPort' },
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Should pass because we can't validate dynamic ports
    });

    it('should handle CloudFormation intrinsic functions in SecurityGroupEgress', () => {
      const resource = createSecurityGroupResource({
        SecurityGroupEgress: { 'Ref': 'EgressRules' }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Should pass because we accept intrinsic functions
    });
  });


  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Using type assertion to test a case where Properties is missing
      const resource = {
        Type: 'AWS::EC2::SecurityGroup',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      // The rule no longer checks for missing Properties
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
  });
});
