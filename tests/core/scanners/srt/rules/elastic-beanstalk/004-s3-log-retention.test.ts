import { describe, it, expect } from 'vitest';
import { ElasticBeanstalk004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/elastic-beanstalk/004-s3-log-retention.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ElasticBeanstalk004Rule', () => {
  const rule = new ElasticBeanstalk004Rule();
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

    it('should return a finding if log streaming is not enabled', () => {
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
      expect(result?.issue).toContain('Elastic Beanstalk environment does not have S3 log retention configured');
    });

    it('should return a finding if log streaming is disabled', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
              OptionName: 'StreamLogs',
              Value: 'false'
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
    });

    it('should return a finding if retention period is not configured', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
              OptionName: 'StreamLogs',
              Value: 'true'
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain("Value '90'");
    });

    it('should not return a finding if log streaming and retention are properly configured', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
              OptionName: 'StreamLogs',
              Value: 'true'
            },
            {
              Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
              OptionName: 'RetentionInDays',
              Value: '256'
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should not return a finding with any configured retention period', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
              OptionName: 'StreamLogs',
              Value: 'true'
            },
            {
              Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
              OptionName: 'RetentionInDays',
              Value: '30'
            }
          ]
        },
        LogicalId: 'TestEnvironment'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should not return a finding with 90+ day retention periods', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ElasticBeanstalk::Environment',
        Properties: {
          ApplicationName: 'MyApp',
          OptionSettings: [
            {
              Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
              OptionName: 'StreamLogs',
              Value: 'true'
            },
            {
              Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
              OptionName: 'RetentionInDays',
              Value: '90'
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