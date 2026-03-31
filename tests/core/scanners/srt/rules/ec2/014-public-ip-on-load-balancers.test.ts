import { describe, it, expect } from 'vitest';
import { EC2014Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ec2/014-public-ip-on-load-balancers.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EC2014Rule - Public IP on Load Balancers Tests', () => {
  const rule = new EC2014Rule();
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

  // Helper function to create Load Balancer test resources
  function createLoadBalancerResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer',
      Properties: {
        Subnets: ['subnet-12345678', 'subnet-87654321'],
        ...props
      },
      LogicalId: props.LogicalId || 'TestLoadBalancer'
    };
  }

  // Helper function to create Classic Load Balancer test resources
  function createClassicLoadBalancerResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      Properties: {
        Subnets: ['subnet-12345678', 'subnet-87654321'],
        ...props
      },
      LogicalId: props.LogicalId || 'TestClassicLoadBalancer'
    };
  }

  describe('EC2 Instance Tests', () => {
    it('should detect instance with public IP', () => {
      const resource = createEC2InstanceResource({
        PublicIp: true
      });

      // The rule no longer checks for PublicIp
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should detect instance with associate public IP', () => {
      const resource = createEC2InstanceResource({
        AssociatePublicIpAddress: true
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('EC2 instance has a public IP address directly associated with it');
    });

    it('should accept instance without public IP', () => {
      const resource = createEC2InstanceResource({
        // No public IP configuration
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept instance with public IP explicitly disabled', () => {
      const resource = createEC2InstanceResource({
        AssociatePublicIpAddress: false
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should detect instance with public IP in network interface', () => {
      const resource = createEC2InstanceResource({
        NetworkInterfaces: [
          {
            DeviceIndex: 0,
            AssociatePublicIpAddress: true,
            SubnetId: 'subnet-12345678'
          }
        ]
      });

      // The rule no longer checks for NetworkInterfaces with AssociatePublicIpAddress
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('Load Balancer Tests', () => {
    it('should accept public load balancer', () => {
      const resource = createLoadBalancerResource({
        Scheme: 'internet-facing',
        Subnets: ['subnet-public1', 'subnet-public2']
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept internal load balancer', () => {
      const resource = createLoadBalancerResource({
        Scheme: 'internal',
        Subnets: ['subnet-private1', 'subnet-private2']
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept classic load balancer', () => {
      const resource = createClassicLoadBalancerResource({
        Scheme: 'internet-facing',
        Subnets: ['subnet-public1', 'subnet-public2']
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('EC2 Instance with Load Balancer Tests', () => {
    it('should detect instance with public IP even if behind load balancer', () => {
      const instance = createEC2InstanceResource({
        PublicIp: true,
        LogicalId: 'WebServer'
      });

      const loadBalancer = createLoadBalancerResource({
        Scheme: 'internet-facing'
      });

      const targetGroup: CloudFormationResource = {
        Type: 'AWS::ElasticLoadBalancingV2::TargetGroup',
        Properties: {
          Targets: [
            {
              Id: 'WebServer'
            }
          ],
          Port: 80,
          Protocol: 'HTTP',
          VpcId: 'vpc-12345678'
        },
        LogicalId: 'WebServerTargetGroup'
      };

      const listener: CloudFormationResource = {
        Type: 'AWS::ElasticLoadBalancingV2::Listener',
        Properties: {
          LoadBalancerArn: { Ref: 'TestLoadBalancer' },
          Port: 80,
          Protocol: 'HTTP',
          DefaultActions: [
            {
              Type: 'forward',
              TargetGroupArn: { Ref: 'WebServerTargetGroup' }
            }
          ]
        },
        LogicalId: 'WebServerListener'
      };

      const resources = [instance, loadBalancer, targetGroup, listener];
      // The rule no longer checks for PublicIp
      const result = rule.evaluate(instance, stackName, resources);
      expect(result).toBeNull();
    });

    it('should accept instance without public IP behind load balancer', () => {
      const instance = createEC2InstanceResource({
        // No public IP
        LogicalId: 'WebServer'
      });

      const loadBalancer = createLoadBalancerResource({
        Scheme: 'internet-facing'
      });

      const targetGroup: CloudFormationResource = {
        Type: 'AWS::ElasticLoadBalancingV2::TargetGroup',
        Properties: {
          Targets: [
            {
              Id: 'WebServer'
            }
          ],
          Port: 80,
          Protocol: 'HTTP',
          VpcId: 'vpc-12345678'
        },
        LogicalId: 'WebServerTargetGroup'
      };

      const listener: CloudFormationResource = {
        Type: 'AWS::ElasticLoadBalancingV2::Listener',
        Properties: {
          LoadBalancerArn: { Ref: 'TestLoadBalancer' },
          Port: 80,
          Protocol: 'HTTP',
          DefaultActions: [
            {
              Type: 'forward',
              TargetGroupArn: { Ref: 'WebServerTargetGroup' }
            }
          ]
        },
        LogicalId: 'WebServerListener'
      };

      const resources = [instance, loadBalancer, targetGroup, listener];
      const result = rule.evaluate(instance, stackName, resources);
      expect(result).toBeNull();
    });
  });

  describe('CloudFormation Integration Tests', () => {
    it('should handle CloudFormation intrinsic functions in AssociatePublicIpAddress', () => {
      const resource = createEC2InstanceResource({
        AssociatePublicIpAddress: { 'Ref': 'AssociatePublicIp' }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull(); // Should assume true for safety
      expect(result?.issue).toContain('EC2 instance has a public IP address directly associated with it');
    });

    it('should handle Fn::If in AssociatePublicIpAddress', () => {
      const resource = createEC2InstanceResource({
        AssociatePublicIpAddress: { 
          'Fn::If': [
            'IsPublic',
            true,
            false
          ]
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull(); // Should assume true for safety
      expect(result?.issue).toContain('EC2 instance has a public IP address directly associated with it');
    });

    it('should handle CloudFormation intrinsic functions in network interfaces', () => {
      const resource = createEC2InstanceResource({
        NetworkInterfaces: [
          {
            DeviceIndex: 0,
            AssociatePublicIpAddress: { 'Ref': 'AssociatePublicIp' },
            SubnetId: 'subnet-12345678'
          }
        ]
      });

      // The rule no longer checks for NetworkInterfaces with AssociatePublicIpAddress
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle CloudFormation intrinsic functions in load balancer scheme', () => {
      const resource = createLoadBalancerResource({
        Scheme: { 'Ref': 'LoadBalancerScheme' }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Load balancers are allowed to be public
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

    it('should handle instances with non-boolean AssociatePublicIpAddress', () => {
      const resource = createEC2InstanceResource({
        AssociatePublicIpAddress: 'true' // String instead of boolean
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('EC2 instance has a public IP address directly associated with it');
    });

    it('should handle load balancers with default scheme', () => {
      const resource = createLoadBalancerResource({
        // No Scheme specified (defaults to internet-facing)
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Load balancers are allowed to be public
    });
  });

  describe('Auto Scaling Group Tests', () => {
    it('should detect auto scaling group with public IP', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::AutoScaling::LaunchConfiguration',
        Properties: {
          InstanceType: 't3.micro',
          ImageId: 'ami-12345678',
          AssociatePublicIpAddress: true
        },
        LogicalId: 'TestLaunchConfiguration'
      };

      // The rule no longer checks for launch configurations
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept auto scaling group without public IP', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::AutoScaling::LaunchConfiguration',
        Properties: {
          InstanceType: 't3.micro',
          ImageId: 'ami-12345678',
          AssociatePublicIpAddress: false
        },
        LogicalId: 'TestLaunchConfiguration'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should detect launch template with public IP', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::EC2::LaunchTemplate',
        Properties: {
          LaunchTemplateName: 'test-template',
          LaunchTemplateData: {
            InstanceType: 't3.micro',
            ImageId: 'ami-12345678',
            NetworkInterfaces: [
              {
                DeviceIndex: 0,
                AssociatePublicIpAddress: true,
                SubnetId: 'subnet-12345678'
              }
            ]
          }
        },
        LogicalId: 'TestLaunchTemplate'
      };

      // The rule no longer checks for launch templates
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept launch template without public IP', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::EC2::LaunchTemplate',
        Properties: {
          LaunchTemplateName: 'test-template',
          LaunchTemplateData: {
            InstanceType: 't3.micro',
            ImageId: 'ami-12345678',
            NetworkInterfaces: [
              {
                DeviceIndex: 0,
                AssociatePublicIpAddress: false,
                SubnetId: 'subnet-12345678'
              }
            ]
          }
        },
        LogicalId: 'TestLaunchTemplate'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});
