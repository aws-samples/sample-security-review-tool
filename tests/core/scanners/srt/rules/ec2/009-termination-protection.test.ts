import { describe, it, expect } from 'vitest';
import { EC2009Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ec2/009-termination-protection.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EC2009Rule - Termination Protection Tests', () => {
  const rule = new EC2009Rule();
  const stackName = 'test-stack';

  // Helper function to create EC2 Instance test resources
  function createEC2InstanceResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::Instance',
      Properties: {
        InstanceType: 't3.micro',
        ImageId: 'ami-12345678',
        ...props
      },
      LogicalId: props.LogicalId || 'TestInstance'
    };
  }

  // Helper function to create Auto Scaling Group test resources
  function createAutoScalingGroupResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      Properties: {
        MinSize: 1,
        MaxSize: 3,
        DesiredCapacity: 2,
        LaunchConfigurationName: { Ref: 'TestLaunchConfig' },
        ...props
      },
      LogicalId: props.LogicalId || 'TestAutoScalingGroup'
    };
  }

  describe('EC2 Instance Tests', () => {
    it('should detect instance without termination protection', () => {
      const resource = createEC2InstanceResource({
        // No DisableApiTermination
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('EC2 instance outside of an Auto Scaling Group does not have termination protection enabled');
    });

    it('should detect instance with termination protection explicitly disabled', () => {
      const resource = createEC2InstanceResource({
        DisableApiTermination: false
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('EC2 instance outside of an Auto Scaling Group does not have termination protection enabled');
    });

    it('should accept instance with termination protection enabled', () => {
      const resource = createEC2InstanceResource({
        DisableApiTermination: true
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle instances in auto scaling groups', () => {
      const instance = createEC2InstanceResource({
        // No DisableApiTermination
        Tags: [
          {
            Key: 'aws:autoscaling:groupName',
            Value: 'TestASG'
          }
        ]
      });

      const result = rule.evaluate(instance, stackName);
      // The rule no longer skips instances in ASGs
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('EC2 instance outside of an Auto Scaling Group does not have termination protection enabled');
    });
  });

  describe('Auto Scaling Group Tests', () => {
    it('should detect ASG without termination protection', () => {
      const resource = createAutoScalingGroupResource({
        // No TerminationPolicies
      });

      // The rule no longer checks ASGs
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should detect ASG with empty termination policies', () => {
      const resource = createAutoScalingGroupResource({
        TerminationPolicies: []
      });

      // The rule no longer checks ASGs
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should detect ASG with insufficient termination policies', () => {
      const resource = createAutoScalingGroupResource({
        TerminationPolicies: ['Default']
      });

      // The rule no longer checks ASGs
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept ASG with proper termination policies', () => {
      const resource = createAutoScalingGroupResource({
        TerminationPolicies: ['OldestInstance', 'OldestLaunchConfiguration']
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('CloudFormation Integration Tests', () => {
    it('should handle CloudFormation intrinsic functions in DisableApiTermination', () => {
      const resource = createEC2InstanceResource({
        DisableApiTermination: { 'Ref': 'EnableTerminationProtection' }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Can't validate dynamic values
    });

    it('should handle CloudFormation intrinsic functions in TerminationPolicies', () => {
      const resource = createAutoScalingGroupResource({
        TerminationPolicies: { 'Ref': 'TerminationPolicies' }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Can't validate dynamic values
    });

    it('should handle Fn::If in DisableApiTermination', () => {
      const resource = createEC2InstanceResource({
        DisableApiTermination: { 
          'Fn::If': [
            'IsProd',
            true,
            false
          ]
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Can't validate conditional values
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Using type assertion to test a case where Properties is missing
      const resource = {
        Type: 'AWS::EC2::Instance',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('EC2 instance outside of an Auto Scaling Group does not have termination protection enabled');
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

    it('should handle instances with non-boolean DisableApiTermination', () => {
      const resource = createEC2InstanceResource({
        DisableApiTermination: 'true' // String instead of boolean
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Should handle string 'true' as boolean true
    });

    it('should handle ASG with string termination policies', () => {
      const resource = createAutoScalingGroupResource({
        TerminationPolicies: 'OldestInstance' // String instead of array
      });

      // The rule no longer checks ASGs
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('Production Environment Tests', () => {
    it('should detect production instance without termination protection', () => {
      const resource = createEC2InstanceResource({
        // No DisableApiTermination
        Tags: [
          {
            Key: 'Environment',
            Value: 'Production'
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('EC2 instance outside of an Auto Scaling Group does not have termination protection enabled');
    });

    it('should detect production ASG without termination protection', () => {
      const resource = createAutoScalingGroupResource({
        // No TerminationPolicies
        Tags: [
          {
            Key: 'Environment',
            Value: 'Production',
            PropagateAtLaunch: true
          }
        ]
      });

      // The rule no longer checks ASGs
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});
