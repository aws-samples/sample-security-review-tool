import { describe, it, expect } from 'vitest';
import { ElasticBeanstalk002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/elastic-beanstalk/002-iam-instance-profile.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ElasticBeanstalk002Rule', () => {
  const rule = new ElasticBeanstalk002Rule();
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

    it('should return a finding if IAM instance profile is missing', () => {
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
      expect(result?.issue).toContain('Elastic Beanstalk environment does not have IAM instance profile configured');
    });

    it('should not return a finding if IAM instance profile is present', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:autoscaling:launchconfiguration',
              OptionName: 'IamInstanceProfile',
              Value: 'aws-elasticbeanstalk-ec2-role'
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should not return a finding if IAM instance profile is present with CloudFormation reference', () => {
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
              Namespace: 'aws:autoscaling:launchconfiguration',
              OptionName: 'IamInstanceProfile',
              Value: { Ref: 'MyInstanceProfile' }
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