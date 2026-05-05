import { describe, it, expect } from 'vitest';
import { ApiGw006Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/006-cloudwatch-logs.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ApiGw006Rule', () => {
  const rule = new ApiGw006Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return a finding if a Stage has no MethodSettings', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' }
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(stage, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
      expect(result?.resourceName).toBe('TestStage');
      expect(result?.issue).toContain('API Gateway does not have CloudWatch logs enabled');
      expect(result?.fix).toContain('Enable CloudWatch logs by setting MethodSettings with LoggingLevel to INFO or ERROR');
    });

    it('should return a finding if a Stage has empty MethodSettings', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          MethodSettings: []
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(stage, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
      expect(result?.resourceName).toBe('TestStage');
      expect(result?.issue).toContain('API Gateway does not have CloudWatch logs enabled');
      expect(result?.fix).toContain('Enable CloudWatch logs by setting MethodSettings with LoggingLevel to INFO or ERROR');
    });

      it('should return a finding if a Stage has MethodSettings with LoggingLevel set to OFF', () => {
        // Arrange
        const stage: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: { Ref: 'TestApi' },
            MethodSettings: [
              {
                HttpMethod: '*',
                ResourcePath: '*',
                LoggingLevel: 'OFF'
              }
            ]
          },
          LogicalId: 'TestStage'
        };

        // Act
        const result = rule.evaluate(stage, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
        expect(result?.resourceName).toBe('TestStage');
        expect(result?.issue).toContain('API Gateway does not have CloudWatch logs enabled');
        expect(result?.fix).toContain('Enable CloudWatch logs by setting MethodSettings with LoggingLevel to INFO or ERROR');
      });

      it('should return a finding if a Stage has MethodSettings with no LoggingLevel', () => {
        // Arrange
        const stage: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: { Ref: 'TestApi' },
            MethodSettings: [
              {
                HttpMethod: '*',
                ResourcePath: '*'
                // No LoggingLevel
              }
            ]
          },
          LogicalId: 'TestStage'
        };

        // Act
        const result = rule.evaluate(stage, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
        expect(result?.resourceName).toBe('TestStage');
        expect(result?.issue).toContain('API Gateway does not have CloudWatch logs enabled');
        expect(result?.fix).toContain('Enable CloudWatch logs by setting MethodSettings with LoggingLevel to INFO or ERROR');
      });

      it('should return a finding if a Stage has MethodSettings for specific methods but no catch-all with logging enabled', () => {
        // Arrange
        const stage: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: { Ref: 'TestApi' },
            MethodSettings: [
              {
                HttpMethod: 'GET',
                ResourcePath: '/users',
                LoggingLevel: 'INFO'
              },
              {
                HttpMethod: 'POST',
                ResourcePath: '/users',
                LoggingLevel: 'OFF'
              }
            ]
          },
          LogicalId: 'TestStage'
        };

        // Act
        const result = rule.evaluate(stage, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
        expect(result?.resourceName).toBe('TestStage');
        expect(result?.issue).toContain('API Gateway does not have CloudWatch logs enabled');
        expect(result?.fix).toContain('Enable CloudWatch logs by setting MethodSettings with LoggingLevel to INFO or ERROR');
      });

    it('should not return a finding if a Stage has MethodSettings with LoggingLevel set to INFO', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          MethodSettings: [
            {
              HttpMethod: '*',
              ResourcePath: '*',
              LoggingLevel: 'INFO'
            }
          ]
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(stage, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if a Stage has MethodSettings with LoggingLevel set to ERROR', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          MethodSettings: [
            {
              HttpMethod: '*',
              ResourcePath: '*',
              LoggingLevel: 'ERROR'
            }
          ]
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(stage, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if a Stage has MethodSettings for all methods with logging enabled', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          MethodSettings: [
            {
              HttpMethod: 'GET',
              ResourcePath: '/users',
              LoggingLevel: 'INFO'
            },
            {
              HttpMethod: 'POST',
              ResourcePath: '/users',
              LoggingLevel: 'ERROR'
            }
          ]
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(stage, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle Ref in LoggingLevel', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          MethodSettings: [
            {
              HttpMethod: '*',
              ResourcePath: '*',
              LoggingLevel: { Ref: 'LogLevel' }
            }
          ]
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(stage, stackName);

      // Assert
      expect(result).toBeNull(); // Should resolve to INFO
    });

      it('should handle Fn::Sub in LoggingLevel', () => {
        // Arrange
        const stageWithInfo: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: { Ref: 'TestApi' },
            MethodSettings: [
              {
                HttpMethod: '*',
                ResourcePath: '*',
                LoggingLevel: { 'Fn::Sub': 'INFO' }
              }
            ]
          },
          LogicalId: 'TestStageInfo'
        };

        const stageWithOff: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: { Ref: 'TestApi' },
            MethodSettings: [
              {
                HttpMethod: '*',
                ResourcePath: '*',
                LoggingLevel: { 'Fn::Sub': 'OFF' }
              }
            ]
          },
          LogicalId: 'TestStageOff'
        };

        // Act
        const infoResult = rule.evaluate(stageWithInfo, stackName);
        const offResult = rule.evaluate(stageWithOff, stackName);

        // Assert
        expect(infoResult).toBeNull(); // Should resolve to INFO
        expect(offResult).not.toBeNull(); // Should resolve to OFF
        expect(offResult?.resourceName).toBe('TestStageOff');
        expect(offResult?.issue).toContain('API Gateway does not have CloudWatch logs enabled');
        expect(offResult?.fix).toContain('Enable CloudWatch logs by setting MethodSettings with LoggingLevel to INFO or ERROR');
      });

    it('should handle Ref in HttpMethod and ResourcePath', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          MethodSettings: [
            {
              HttpMethod: { Ref: 'HttpMethod' },
              ResourcePath: { Ref: 'ResourcePath' },
              LoggingLevel: 'INFO'
            }
          ]
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(stage, stackName);

      // Assert
      expect(result).toBeNull(); // Should resolve HttpMethod and ResourcePath to '*'
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
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });
});
