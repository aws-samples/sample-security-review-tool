import { describe, it, expect } from 'vitest';
import { ElasticBeanstalk003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/elastic-beanstalk/003-platform-updates.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ElasticBeanstalk003Rule', () => {
  const rule = new ElasticBeanstalk003Rule();
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

    it('should return a finding if managed actions are not enabled', () => {
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
      expect(result?.issue).toContain('Elastic Beanstalk environment does not have platform updates enabled');
    });

    it('should return a finding if managed actions are disabled', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:elasticbeanstalk:managedactions',
              OptionName: 'ManagedActionsEnabled',
              Value: 'false'
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
    });

    it('should return a finding if update level is not set to minor', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:elasticbeanstalk:managedactions',
              OptionName: 'ManagedActionsEnabled',
              Value: 'true'
            },
            {
              Namespace: 'aws:elasticbeanstalk:managedactions:platformupdate',
              OptionName: 'UpdateLevel',
              Value: 'patch'
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
    });

    it('should not return a finding if platform updates are properly configured', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:elasticbeanstalk:managedactions',
              OptionName: 'ManagedActionsEnabled',
              Value: 'true'
            },
            {
              Namespace: 'aws:elasticbeanstalk:managedactions:platformupdate',
              OptionName: 'UpdateLevel',
              Value: 'minor'
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