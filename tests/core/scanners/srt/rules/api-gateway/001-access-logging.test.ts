import { describe, it, expect } from 'vitest';
import { ApiGw001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/001-access-logging';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ApiGw001Rule', () => {
  const rule = new ApiGw001Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return a finding if an API Gateway Stage has no AccessLogSetting', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' }
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(resource, stackName, [resource]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
      expect(result?.resourceName).toBe('TestStage');
      expect(result?.issue).toContain('API Gateway does not have access logging enabled with proper retention');
      expect(result?.fix).toContain('Add AccessLogSetting with DestinationArn and Format properties');
    });

    it('should return a finding if an API Gateway Stage has AccessLogSetting but no DestinationArn', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          AccessLogSetting: {
            Format: '$context.requestId'
          }
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(resource, stackName, [resource]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
      expect(result?.resourceName).toBe('TestStage');
      expect(result?.issue).toContain('API Gateway does not have access logging enabled with proper retention');
      expect(result?.fix).toContain('Ensure both DestinationArn and Format properties are specified in AccessLogSetting');
    });

    it('should return a finding if an API Gateway Stage has AccessLogSetting but no Format', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          AccessLogSetting: {
            DestinationArn: 'arn:aws:logs:us-east-1:123456789012:log-group:api-gateway-logs'
          }
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(resource, stackName, [resource]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
      expect(result?.resourceName).toBe('TestStage');
      expect(result?.issue).toContain('API Gateway does not have access logging enabled with proper retention');
      expect(result?.fix).toContain('Ensure both DestinationArn and Format properties are specified in AccessLogSetting');
    });

    it('should return a finding if an API Gateway Stage references a log group without retention period', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          AccessLogSetting: {
            DestinationArn: { Ref: 'ApiLogGroup' },
            Format: '$context.requestId'
          }
        },
        LogicalId: 'TestStage'
      };

      const logGroup: CloudFormationResource = {
        Type: 'AWS::Logs::LogGroup',
        Properties: {
          LogGroupName: 'api-gateway-logs'
        },
        LogicalId: 'ApiLogGroup'
      };

      // Act
      const result = rule.evaluate(stage, stackName, [stage, logGroup]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
      expect(result?.resourceName).toBe('TestStage');
      expect(result?.issue).toContain('API Gateway does not have access logging enabled with proper retention');
      expect(result?.issue).toContain('log group has no retention period');
    });

    it('should return a finding if an API Gateway Stage references a log group that cannot be found', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          AccessLogSetting: {
            DestinationArn: { Ref: 'NonExistentLogGroup' },
            Format: '$context.requestId'
          }
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(stage, stackName, [stage]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
      expect(result?.resourceName).toBe('TestStage');
      expect(result?.issue).toContain('API Gateway does not have access logging enabled with proper retention');
      expect(result?.issue).toContain('referenced log group not found or retention not verifiable');
    });

    it('should return a finding for API Gateway log groups without retention period', () => {
      // Arrange
      const logGroup: CloudFormationResource = {
        Type: 'AWS::Logs::LogGroup',
        Properties: {
          LogGroupName: 'API-Gateway-Execution-Logs'
        },
        LogicalId: 'ApiLogGroup'
      };

      // Act
      const result = rule.evaluate(logGroup, stackName, [logGroup]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Logs::LogGroup');
      expect(result?.resourceName).toBe('ApiLogGroup');
      expect(result?.issue).toContain('API Gateway does not have access logging enabled with proper retention');
      expect(result?.issue).toContain('API Gateway log group has no retention period');
    });

    it('should not return a finding for non-API Gateway log groups without retention period', () => {
      // Arrange
      const logGroup: CloudFormationResource = {
        Type: 'AWS::Logs::LogGroup',
        Properties: {
          LogGroupName: 'lambda-logs'
        },
        LogicalId: 'LambdaLogGroup'
      };

      // Act
      const result = rule.evaluate(logGroup, stackName, [logGroup]);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if an API Gateway Stage has proper logging with retention', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          AccessLogSetting: {
            DestinationArn: { Ref: 'ApiLogGroup' },
            Format: '$context.requestId'
          }
        },
        LogicalId: 'TestStage'
      };

      const logGroup: CloudFormationResource = {
        Type: 'AWS::Logs::LogGroup',
        Properties: {
          LogGroupName: 'api-gateway-logs',
          RetentionInDays: 30
        },
        LogicalId: 'ApiLogGroup'
      };

      // Act
      const result = rule.evaluate(stage, stackName, [stage, logGroup]);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding for API Gateway log groups with retention period', () => {
      // Arrange
      const logGroup: CloudFormationResource = {
        Type: 'AWS::Logs::LogGroup',
        Properties: {
          LogGroupName: 'API-Gateway-Execution-Logs',
          RetentionInDays: 90
        },
        LogicalId: 'ApiLogGroup'
      };

      // Act
      const result = rule.evaluate(logGroup, stackName, [logGroup]);

      // Assert
      expect(result).toBeNull();
    });

      it('should handle string ARN in DestinationArn', () => {
        // Arrange
        const stage: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: { Ref: 'TestApi' },
            AccessLogSetting: {
              DestinationArn: 'arn:aws:logs:us-east-1:123456789012:log-group:api-gateway-logs',
              Format: '$context.requestId'
            }
          },
          LogicalId: 'TestStage'
        };

        const logGroup: CloudFormationResource = {
          Type: 'AWS::Logs::LogGroup',
          Properties: {
            LogGroupName: 'api-gateway-logs',
            RetentionInDays: 30
          },
          LogicalId: 'ApiLogGroup'
        };

        // Act
        const result = rule.evaluate(stage, stackName, [stage, logGroup]);

        // Assert
        // The rule is able to extract the log group name from the ARN and find the matching log group
        // Since the log group has a retention period, no finding is returned
        expect(result).toBeNull();
      });

    it('should handle Fn::Sub in DestinationArn', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          AccessLogSetting: {
            DestinationArn: { 
              'Fn::Sub': 'arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:${ApiLogGroup}' 
            },
            Format: '$context.requestId'
          }
        },
        LogicalId: 'TestStage'
      };

      const logGroup: CloudFormationResource = {
        Type: 'AWS::Logs::LogGroup',
        Properties: {
          LogGroupName: { 'Fn::Sub': '${AWS::StackName}-api-logs' },
          RetentionInDays: 30
        },
        LogicalId: 'ApiLogGroup'
      };

      // Act
      const result = rule.evaluate(stage, stackName, [stage, logGroup]);

      // Assert
      expect(result).toBeNull(); // The rule should be able to extract ApiLogGroup from Fn::Sub
    });

    it('should handle Fn::Join in DestinationArn', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          AccessLogSetting: {
            DestinationArn: { 
              'Fn::Join': ['', [
                'arn:aws:logs:', 
                { Ref: 'AWS::Region' }, 
                ':', 
                { Ref: 'AWS::AccountId' }, 
                ':log-group:', 
                { Ref: 'ApiLogGroup' }
              ]] 
            },
            Format: '$context.requestId'
          }
        },
        LogicalId: 'TestStage'
      };

      const logGroup: CloudFormationResource = {
        Type: 'AWS::Logs::LogGroup',
        Properties: {
          LogGroupName: 'api-gateway-logs',
          RetentionInDays: 30
        },
        LogicalId: 'ApiLogGroup'
      };

      // Act
      const result = rule.evaluate(stage, stackName, [stage, logGroup]);

      // Assert
      expect(result).toBeNull(); // The rule should be able to extract ApiLogGroup from Fn::Join
    });

    it('should return null for non-applicable resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName, [resource]);

      // Assert
      expect(result).toBeNull();
    });
  });
});
