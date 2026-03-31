import { describe, it, expect } from 'vitest';
import { ElasticBeanstalk001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/elastic-beanstalk/001-vpc-configuration.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ElasticBeanstalk001Rule', () => {
  const rule = new ElasticBeanstalk001Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return null for non-applicable resource types', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {},
        LogicalId: 'TestBucket'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should return a finding if VPC configuration is missing', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:autoscaling:launchconfiguration',
              OptionName: 'InstanceType',
              Value: 't3.micro'
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ElasticBeanstalk::Environment');
      expect(result?.resourceName).toBe('TestEnvironment');
      expect(result?.issue).toContain('Elastic Beanstalk environment is not configured with VPC');
    });

    it('should not return a finding if VPC configuration is present', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:ec2:vpc',
              OptionName: 'VPCId',
              Value: 'vpc-12345678'
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should not return a finding if VPC configuration is present with other settings', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:autoscaling:launchconfiguration',
              OptionName: 'InstanceType',
              Value: 't3.micro'
            },
            {
              Namespace: 'aws:ec2:vpc',
              OptionName: 'VPCId',
              Value: { Ref: 'MyVPC' }
            },
            {
              Namespace: 'aws:ec2:vpc',
              OptionName: 'Subnets',
              Value: 'subnet-12345678,subnet-87654321'
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should not return a finding if VPC is configured via Subnets only', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:ec2:vpc',
              OptionName: 'Subnets',
              Value: 'subnet-12345678,subnet-87654321'
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should not return a finding if VPC is configured via ELBSubnets', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:ec2:vpc',
              OptionName: 'ELBSubnets',
              Value: 'subnet-12345678,subnet-87654321'
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should not return a finding if VPC is configured via SecurityGroups in launch configuration', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:autoscaling:launchconfiguration',
              OptionName: 'SecurityGroups',
              Value: 'sg-12345678'
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should not return a finding if VPC is configured via SecurityGroups in ELB', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:elb:loadbalancer',
              OptionName: 'SecurityGroups',
              Value: { Ref: 'MySecurityGroup' }
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});