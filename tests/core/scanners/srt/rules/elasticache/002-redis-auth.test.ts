import { describe, it, expect } from 'vitest';
import { Elasticache002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/elasticache/002-redis-auth.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Elasticache002Rule', () => {
  const rule = new Elasticache002Rule();
  const stackName = 'test-stack';

  // Helper function to create ReplicationGroup test resources
  function createReplicationGroupResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::ElastiCache::ReplicationGroup',
      Properties: {
        ReplicationGroupDescription: 'Test Redis Cluster',
        Engine: 'redis',
        CacheNodeType: 'cache.t3.micro',
        NumCacheClusters: 1,
        ...props
      },
      LogicalId: props.LogicalId || 'TestRedisCluster'
    };
  }

  // Helper function to create CacheCluster test resources
  function createCacheClusterResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::ElastiCache::CacheCluster',
      Properties: {
        Engine: 'redis',
        CacheNodeType: 'cache.t3.micro',
        NumCacheNodes: 1,
        ...props
      },
      LogicalId: props.LogicalId || 'TestCacheCluster'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('ELASTICACHE-002');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to ElastiCache ReplicationGroup and CacheCluster resources', () => {
      expect(rule.appliesTo('AWS::ElastiCache::ReplicationGroup')).toBe(true);
      expect(rule.appliesTo('AWS::ElastiCache::CacheCluster')).toBe(true);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('ReplicationGroup Tests', () => {
    it('should pass when AuthToken and TransitEncryptionEnabled are properly configured', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        AuthToken: 'MySecureAuthToken',
        TransitEncryptionEnabled: true
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when AuthToken is a CloudFormation reference and TransitEncryptionEnabled is true', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        AuthToken: { Ref: 'RedisAuthToken' },
        TransitEncryptionEnabled: true
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when AuthToken uses CloudFormation intrinsic functions and TransitEncryptionEnabled is true', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        AuthToken: { 'Fn::GetAtt': ['SecretResource', 'SecretString'] },
        TransitEncryptionEnabled: true
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should fail when AuthToken is missing but TransitEncryptionEnabled is true', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        TransitEncryptionEnabled: true
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ElastiCache::ReplicationGroup');
      expect(result?.resourceName).toBe('TestRedisCluster');
      expect(result?.issue).toContain('ElastiCache Redis cluster not configured with Redis AUTH');
      expect(result?.fix).toContain('Set AuthToken property');
    });

    it('should fail when AuthToken is provided but TransitEncryptionEnabled is false', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        AuthToken: 'MySecureAuthToken',
        TransitEncryptionEnabled: false
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ElastiCache::ReplicationGroup');
      expect(result?.resourceName).toBe('TestRedisCluster');
      expect(result?.issue).toContain('ElastiCache Redis cluster not configured with Redis AUTH');
      expect(result?.fix).toContain('Set TransitEncryptionEnabled to true');
    });

    it('should fail when both AuthToken and TransitEncryptionEnabled are missing', () => {
      // Arrange
      const resource = createReplicationGroupResource({});

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ElastiCache::ReplicationGroup');
      expect(result?.resourceName).toBe('TestRedisCluster');
      expect(result?.issue).toContain('ElastiCache Redis cluster not configured with Redis AUTH');
      expect(result?.fix).toContain('Set AuthToken property');
      expect(result?.fix).toContain('Set TransitEncryptionEnabled to true');
    });

    it('should fail when AuthToken is an empty string', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        AuthToken: '',
        TransitEncryptionEnabled: true
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ElastiCache::ReplicationGroup');
      expect(result?.resourceName).toBe('TestRedisCluster');
      expect(result?.issue).toContain('ElastiCache Redis cluster not configured with Redis AUTH');
      expect(result?.fix).toContain('Set AuthToken property');
    });
  });

  describe('CacheCluster Tests', () => {
    it('should fail for Redis CacheCluster resources (as they do not support AuthToken)', () => {
      // Arrange
      const resource = createCacheClusterResource({
        Engine: 'redis'
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ElastiCache::CacheCluster');
      expect(result?.resourceName).toBe('TestCacheCluster');
      expect(result?.issue).toContain('ElastiCache Redis cluster not configured with Redis AUTH');
      expect(result?.fix).toContain('AWS::ElastiCache::CacheCluster does not support Redis AUTH');
    });

    it('should skip non-Redis (Memcached) CacheCluster resources', () => {
      // Arrange
      const resource = createCacheClusterResource({
        Engine: 'memcached'
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Engine Type Tests', () => {
    it('should skip resources with no engine specified (defaults to Memcached)', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        Engine: undefined
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle case-insensitive engine name', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        Engine: 'ReDiS',
        AuthToken: 'MySecureAuthToken',
        TransitEncryptionEnabled: true
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Arrange
      const resource = {
        Type: 'AWS::ElastiCache::ReplicationGroup',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull(); // Should skip as no engine is specified
    });

    it('should handle CloudFormation intrinsic functions in TransitEncryptionEnabled', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        AuthToken: 'MySecureAuthToken',
        TransitEncryptionEnabled: { Ref: 'EnableTransitEncryption' }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      // Since we can't evaluate the Ref at test time, we should fail safe
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ElastiCache::ReplicationGroup');
      expect(result?.resourceName).toBe('TestRedisCluster');
      expect(result?.issue).toContain('ElastiCache Redis cluster not configured with Redis AUTH');
    });

    it('should handle CloudFormation Fn::If in AuthToken', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        AuthToken: { 
          'Fn::If': [
            'IsProduction',
            'MySecureAuthToken',
            { Ref: 'AWS::NoValue' }
          ]
        },
        TransitEncryptionEnabled: true
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      // Since we can't evaluate the Fn::If at test time, but the object is not empty
      // the hasAuthTokenConfigured should return true
      expect(result).toBeNull();
    });

    it('should ignore non-applicable resources', () => {
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
