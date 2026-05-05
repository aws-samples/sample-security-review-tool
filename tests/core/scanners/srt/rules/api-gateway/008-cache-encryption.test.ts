import { describe, it, expect } from 'vitest';
import { ApiGw008Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/008-cache-encryption.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ApiGw008Rule', () => {
  const rule = new ApiGw008Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return null if caching is not enabled', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          CacheClusterEnabled: false
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(stage, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return a finding if caching is enabled but no method settings are specified', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          CacheClusterEnabled: true
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(stage, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
      expect(result?.resourceName).toBe('TestStage');
      expect(result?.issue).toContain('API Gateway stage cache encryption is not enabled');
      expect(result?.issue).toContain('cache is enabled but encryption is not configured');
    });

    it('should return a finding if caching is enabled but method settings are empty', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          CacheClusterEnabled: true,
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
      expect(result?.issue).toContain('API Gateway stage cache encryption is not enabled');
      expect(result?.issue).toContain('cache is enabled but encryption is not configured');
    });

    it('should return a finding if catch-all method setting does not enable cache encryption', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          CacheClusterEnabled: true,
          MethodSettings: [
            {
              HttpMethod: '*',
              ResourcePath: '*',
              CacheDataEncrypted: false
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
      expect(result?.issue).toContain('API Gateway stage cache encryption is not enabled');
      expect(result?.issue).toContain('catch-all method setting does not enable cache encryption');
    });

    it('should return a finding if catch-all method setting does not specify cache encryption', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          CacheClusterEnabled: true,
          MethodSettings: [
            {
              HttpMethod: '*',
              ResourcePath: '*'
              // No CacheDataEncrypted
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
      expect(result?.issue).toContain('API Gateway stage cache encryption is not enabled');
      expect(result?.issue).toContain('catch-all method setting does not enable cache encryption');
    });

    it('should return a finding if some methods have caching enabled but not encrypted', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          CacheClusterEnabled: true,
          MethodSettings: [
            {
              HttpMethod: 'GET',
              ResourcePath: '/users',
              CachingEnabled: true,
              CacheDataEncrypted: false
            },
            {
              HttpMethod: 'POST',
              ResourcePath: '/users',
              CachingEnabled: true,
              CacheDataEncrypted: true
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
      expect(result?.issue).toContain('API Gateway stage cache encryption is not enabled');
      expect(result?.issue).toContain('1 methods have caching enabled but not encrypted');
    });

    it('should return a finding if stage has caching enabled but no method settings configure encryption', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          CacheClusterEnabled: true,
          MethodSettings: [
            {
              HttpMethod: 'GET',
              ResourcePath: '/users'
              // No caching settings
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
      expect(result?.issue).toContain('API Gateway stage cache encryption is not enabled');
      expect(result?.issue).toContain('stage has caching enabled but no method settings configure encryption');
    });

    it('should not return a finding if catch-all method setting enables cache encryption', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          CacheClusterEnabled: true,
          MethodSettings: [
            {
              HttpMethod: '*',
              ResourcePath: '*',
              CacheDataEncrypted: true
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

    it('should not return a finding if all methods with caching have encryption enabled', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          CacheClusterEnabled: true,
          MethodSettings: [
            {
              HttpMethod: 'GET',
              ResourcePath: '/users',
              CachingEnabled: true,
              CacheDataEncrypted: true
            },
            {
              HttpMethod: 'POST',
              ResourcePath: '/users',
              CachingEnabled: true,
              CacheDataEncrypted: true
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

    it('should handle Ref in CacheClusterEnabled', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          CacheClusterEnabled: { Ref: 'CacheEnabled' },
          MethodSettings: [
            {
              HttpMethod: '*',
              ResourcePath: '*',
              CacheDataEncrypted: true
            }
          ]
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(stage, stackName);

      // Assert
      expect(result).toBeNull(); // Should resolve CacheClusterEnabled to true and CacheDataEncrypted is true
    });

    it('should handle Ref in CacheDataEncrypted', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          CacheClusterEnabled: true,
          MethodSettings: [
            {
              HttpMethod: '*',
              ResourcePath: '*',
              CacheDataEncrypted: { Ref: 'Encrypted' }
            }
          ]
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(stage, stackName);

      // Assert
      expect(result).toBeNull(); // Should resolve CacheDataEncrypted to true
    });

    it('should handle Fn::If in CacheDataEncrypted', () => {
      // Arrange
      const stage: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: { Ref: 'TestApi' },
          CacheClusterEnabled: true,
          MethodSettings: [
            {
              HttpMethod: '*',
              ResourcePath: '*',
              CacheDataEncrypted: { 'Fn::If': ['Condition', true, false] }
            }
          ]
        },
        LogicalId: 'TestStage'
      };

      // Act
      const result = rule.evaluate(stage, stackName);

      // Assert
      expect(result).toBeNull(); // Should resolve CacheDataEncrypted to true
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
