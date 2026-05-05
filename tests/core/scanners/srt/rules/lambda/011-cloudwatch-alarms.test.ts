import { describe, it, expect } from 'vitest';
import { CompLamb011Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/lambda/011-cloudwatch-alarms.cf.js';
import { Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('CompLamb011Rule - CloudWatch Alarms Tests', () => {
  const rule = new CompLamb011Rule();
  const stackName = 'test-stack';

  // Helper function to create Lambda test resources
  function createLambdaResource(props: Record<string, any> = {}): Resource {
    return {
      Type: 'AWS::Lambda::Function',
      Properties: {
        Handler: 'index.handler',
        Runtime: 'nodejs18.x',
        Code: {
          S3Bucket: 'my-bucket',
          S3Key: 'my-key'
        },
        ...props
      },
      Metadata: props.Metadata
    };
  }

  // Helper function to create CloudWatch Alarm resources
  function createCloudWatchAlarm(props: Record<string, any> = {}): Resource {
    const defaultProperties = {
      AlarmName: 'TestAlarm',
      MetricName: 'Errors',
      Namespace: 'AWS/Lambda',
      Statistic: 'Sum',
      Period: 300,
      EvaluationPeriods: 1,
      Threshold: 1,
      ComparisonOperator: 'GreaterThanOrEqualToThreshold',
      Dimensions: [
        {
          Name: 'FunctionName',
          Value: 'TestLambda'
        }
      ]
    };

    return {
      Type: 'AWS::CloudWatch::Alarm',
      Properties: {
        ...defaultProperties,
        ...props.Properties
      }
    };
  }

  // Helper function to create CloudFormation templates
  function createTemplate(resources: Record<string, Resource>): Template {
    return {
      Resources: resources
    };
  }

  describe('Basic Configuration Tests', () => {
    it('should return null for non-Lambda resources', () => {
      const s3Resource: Resource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'test-bucket'
        }
      };

      const template = createTemplate({ TestBucket: s3Resource });
      const result = rule.evaluateResource(stackName, template, s3Resource);
      
      expect(result).toBeNull();
    });

    it('should detect Lambda function without alarms', () => {
      const lambdaResource = createLambdaResource();
      const template = createTemplate({ TestLambda: lambdaResource });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function lacks CloudWatch alarms for monitoring');
      expect(result?.fix).toContain('Create CloudWatch alarms for the following Lambda metrics: Errors,Throttles,Duration,Invocations,ConcurrentExecutions,DeadLetterErrors');
      expect(result?.priority).toBe('HIGH');
      expect(result?.check_id).toBe('LAMBDA-011');
    });

    it('should accept Lambda function with CloudWatch alarms', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          MetricName: 'Errors',
          Namespace: 'AWS/Lambda',
          Dimensions: [
            {
              Name: 'FunctionName',
              Value: 'TestLambda'
            }
          ]
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).toBeNull();
    });
  });

  describe('Alarm Detection Tests', () => {
    it('should detect alarms with correct AWS/Lambda namespace', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          Namespace: 'AWS/Lambda',
          Dimensions: [
            {
              Name: 'FunctionName',
              Value: 'TestLambda'
            }
          ]
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).toBeNull();
    });

    it('should ignore alarms with wrong namespace', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          Namespace: 'AWS/EC2' // Wrong namespace - keeps other default properties
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).not.toBeNull(); // Should fail because wrong namespace
    });

    it('should ignore alarms missing FunctionName dimension', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          Dimensions: [
            {
              Name: 'InstanceId', // Wrong dimension
              Value: 'i-1234567890abcdef0'
            }
          ]
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).not.toBeNull(); // Should fail because missing FunctionName dimension
    });

    it('should ignore alarms with empty dimensions', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          Dimensions: []
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).not.toBeNull(); // Should fail because no dimensions
    });
  });

  describe('Reference Resolution Tests', () => {
    it('should handle direct string references to Lambda logical ID', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          Namespace: 'AWS/Lambda',
          Dimensions: [
            {
              Name: 'FunctionName',
              Value: 'TestLambda' // Direct string reference
            }
          ]
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).toBeNull();
    });

    it('should handle Ref references to Lambda functions', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          Namespace: 'AWS/Lambda',
          Dimensions: [
            {
              Name: 'FunctionName',
              Value: { Ref: 'TestLambda' } // Ref reference
            }
          ]
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).toBeNull();
    });

    it('should handle Fn::GetAtt references to Lambda functions', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          Namespace: 'AWS/Lambda',
          Dimensions: [
            {
              Name: 'FunctionName',
              Value: { 'Fn::GetAtt': ['TestLambda', 'Arn'] } // GetAtt reference
            }
          ]
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).toBeNull();
    });

    it('should handle DEFAULT parameter values', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          Namespace: 'AWS/Lambda',
          Dimensions: [
            {
              Name: 'FunctionName',
              Value: 'DEFAULT' // Resolved parameter default - matches any Lambda
            }
          ]
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).toBeNull(); // DEFAULT should match any Lambda
    });

    it('should ignore invalid Ref references', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          Namespace: 'AWS/Lambda',
          Dimensions: [
            {
              Name: 'FunctionName',
              Value: { Ref: 'NonExistentResource' } // Invalid Ref - doesn't match TestLambda
            }
          ]
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).not.toBeNull(); // Should fail because alarm doesn't reference our Lambda
    });
  });

  describe('CloudFormation Integration Tests', () => {
    it('should handle templates with multiple Lambda functions and alarms', () => {
      const lambda1 = createLambdaResource();
      const lambda2 = createLambdaResource();
      const alarm1 = createCloudWatchAlarm({
        Properties: {
          Namespace: 'AWS/Lambda',
          Dimensions: [
            {
              Name: 'FunctionName',
              Value: { Ref: 'TestLambda1' } // Reference the first Lambda
            }
          ]
        }
      });

      const template = createTemplate({
        TestLambda1: lambda1,
        TestLambda2: lambda2,
        TestAlarm1: alarm1
      });
      
      // Lambda1 should pass (has alarm)
      const result1 = rule.evaluateResource(stackName, template, lambda1);
      expect(result1).toBeNull();
      
      // Lambda2 should fail (no alarm)
      const result2 = rule.evaluateResource(stackName, template, lambda2);
      expect(result2).not.toBeNull();
    });

    it('should handle complex CloudFormation template structures', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          Namespace: 'AWS/Lambda',
          MetricName: 'Duration',
          Dimensions: [
            {
              Name: 'FunctionName',
              Value: { Ref: 'MyLambdaFunction' } // This references the Lambda correctly
            }
          ],
          AlarmActions: [
            { Ref: 'MySNSTopic' }
          ]
        }
      });

      const snsResource: Resource = {
        Type: 'AWS::SNS::Topic',
        Properties: {
          TopicName: 'MyAlarmTopic'
        }
      };

      const template = createTemplate({
        MyLambdaFunction: lambdaResource,
        MyLambdaAlarm: alarmResource,
        MySNSTopic: snsResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle Lambda resource without Properties', () => {
      const lambdaResource: Resource = {
        Type: 'AWS::Lambda::Function'
        // Missing Properties
      };

      const template = createTemplate({ TestLambda: lambdaResource });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).not.toBeNull();
    });

    it('should handle template without Resources', () => {
      const lambdaResource = createLambdaResource();
      const template: Template = {}; // Missing Resources
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).toBeNull(); // Should return null when can't find logical ID
    });

    it('should handle alarm without Properties', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource: Resource = {
        Type: 'AWS::CloudWatch::Alarm'
        // Missing Properties
      };

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).not.toBeNull();
    });

    it('should handle alarm with malformed dimensions', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          Dimensions: 'not-an-array' // Malformed dimensions - should be ignored
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).not.toBeNull(); // Should fail because malformed alarm is ignored
    });

    it('should handle dimension without Value property', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          Dimensions: [
            {
              Name: 'FunctionName'
              // Missing Value - should be ignored
            }
          ]
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).not.toBeNull(); // Should fail because dimension is invalid
    });

    it('should handle resource not found in template', () => {
      const lambdaResource = createLambdaResource();
      const template = createTemplate({}); // Empty resources
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).toBeNull(); // Should return null when can't find logical ID
    });

    it('should handle invalid Fn::GetAtt structure', () => {
      const lambdaResource = createLambdaResource();
      const alarmResource = createCloudWatchAlarm({
        Properties: {
          Dimensions: [
            {
              Name: 'FunctionName',
              Value: { 'Fn::GetAtt': 'InvalidStructure' } // Should be array - invalid
            }
          ]
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        TestAlarm: alarmResource
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).not.toBeNull(); // Should fail because GetAtt structure is invalid
    });
  });

  describe('Multiple Alarms Scenarios', () => {
    it('should detect when at least one alarm exists for Lambda function', () => {
      const lambdaResource = createLambdaResource();
      const errorAlarm = createCloudWatchAlarm({
        Properties: {
          MetricName: 'Errors',
          Namespace: 'AWS/Lambda',
          Dimensions: [
            {
              Name: 'FunctionName',
              Value: 'TestLambda'
            }
          ]
        }
      });
      const throttleAlarm = createCloudWatchAlarm({
        Properties: {
          MetricName: 'Throttles',
          Namespace: 'AWS/Lambda',
          Dimensions: [
            {
              Name: 'FunctionName',
              Value: 'TestLambda'
            }
          ]
        }
      });

      const template = createTemplate({
        TestLambda: lambdaResource,
        ErrorAlarm: errorAlarm,
        ThrottleAlarm: throttleAlarm
      });
      
      const result = rule.evaluateResource(stackName, template, lambdaResource);
      expect(result).toBeNull(); // Should pass with multiple alarms
    });
  });
});
