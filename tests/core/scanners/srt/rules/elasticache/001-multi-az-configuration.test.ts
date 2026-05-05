import { describe, it, expect } from 'vitest';
import { Elasticache001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/elasticache/001-multi-az-configuration.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Elasticache001Rule', () => {
  const rule = new Elasticache001Rule();
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
      expect(rule.id).toBe('ELASTICACHE-001');
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
    it('should pass when AutomaticFailoverEnabled is true', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        AutomaticFailoverEnabled: true
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when NumCacheClusters > 1', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        AutomaticFailoverEnabled: false,
        NumCacheClusters: 2
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when NumNodeGroups > 1', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        AutomaticFailoverEnabled: false,
        NumCacheClusters: undefined,
        NumNodeGroups: 2
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should fail when AutomaticFailoverEnabled is false and NumCacheClusters = 1', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        AutomaticFailoverEnabled: false,
        NumCacheClusters: 1
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ElastiCache::ReplicationGroup');
      expect(result?.resourceName).toBe('TestRedisCluster');
      expect(result?.issue).toContain('ElastiCache Redis cluster not configured for multi-AZ deployment');
    });

    it('should fail when AutomaticFailoverEnabled is missing and no multi-node configuration', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        // AutomaticFailoverEnabled is not set
        NumCacheClusters: 1
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ElastiCache::ReplicationGroup');
      expect(result?.resourceName).toBe('TestRedisCluster');
      expect(result?.issue).toContain('ElastiCache Redis cluster not configured for multi-AZ deployment');
    });
  });

  describe('CacheCluster Tests', () => {
    it('should fail for Redis engine with single node', () => {
      // Arrange
      const resource = createCacheClusterResource({
        Engine: 'redis',
        NumCacheNodes: 1
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ElastiCache::CacheCluster');
      expect(result?.resourceName).toBe('TestCacheCluster');
      expect(result?.issue).toContain('ElastiCache Redis cluster not configured for multi-AZ deployment');
    });

    it('should pass for Redis engine with multiple nodes', () => {
      // Arrange
      const resource = createCacheClusterResource({
        Engine: 'redis',
        NumCacheNodes: 2
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass for non-Redis engine', () => {
      // Arrange
      const resource = createCacheClusterResource({
        Engine: 'memcached',
        NumCacheNodes: 1
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
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ElastiCache::ReplicationGroup');
      expect(result?.resourceName).toBe('MissingProperties');
      expect(result?.issue).toContain('ElastiCache Redis cluster not configured for multi-AZ deployment');
    });

    it('should handle CloudFormation intrinsic functions in AutomaticFailoverEnabled', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        AutomaticFailoverEnabled: { Ref: 'EnableMultiAZ' }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      // Since we can't evaluate the Ref at test time, we should fail safe
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ElastiCache::ReplicationGroup');
      expect(result?.resourceName).toBe('TestRedisCluster');
      expect(result?.issue).toContain('ElastiCache Redis cluster not configured for multi-AZ deployment');
    });

    it('should handle CloudFormation Fn::If in AutomaticFailoverEnabled', () => {
      // Arrange
      const resource = createReplicationGroupResource({
        AutomaticFailoverEnabled: { 
          'Fn::If': [
            'IsProduction',
            true,
            false
          ]
        }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      // Since we can't evaluate the Fn::If at test time, we should fail safe
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ElastiCache::ReplicationGroup');
      expect(result?.resourceName).toBe('TestRedisCluster');
      expect(result?.issue).toContain('ElastiCache Redis cluster not configured for multi-AZ deployment');
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
