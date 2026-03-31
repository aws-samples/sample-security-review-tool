import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Elasticache001Rule extends BaseRule {
  constructor() {
    super(
      'ELASTICACHE-001',
      'HIGH',
      'ElastiCache Redis cluster not configured for multi-AZ deployment',
      ['AWS::ElastiCache::ReplicationGroup', 'AWS::ElastiCache::CacheCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const resourceType = resource.Type;

    if (resourceType === 'AWS::ElastiCache::ReplicationGroup') {
      return this.evaluateReplicationGroup(resource, stackName);
    } else if (resourceType === 'AWS::ElastiCache::CacheCluster') {
      return this.evaluateCacheCluster(resource, stackName);
    }

    return null;
  }

  private evaluateReplicationGroup(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const properties = resource.Properties;

    // Check if AutomaticFailoverEnabled is true (indicates multi-AZ)
    const automaticFailover = properties?.AutomaticFailoverEnabled;
    const numCacheClusters = properties?.NumCacheClusters;
    const nodeGroups = properties?.NumNodeGroups;

    // For replication groups, multi-AZ requires either:
    // 1. AutomaticFailoverEnabled: true, OR
    // 2. Multiple cache clusters/node groups
    const hasMultiAZ = automaticFailover === true ||
      (numCacheClusters && numCacheClusters > 1) ||
      (nodeGroups && nodeGroups > 1);

    if (!hasMultiAZ) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set AutomaticFailoverEnabled to true and ensure NumCacheClusters > 1 for multi-AZ deployment.`
      );
    }

    return null;
  }

  private evaluateCacheCluster(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const properties = resource.Properties;

    // Single CacheCluster resources are inherently single-AZ
    // Check if it's a single node Redis cluster
    const engine = properties?.Engine?.toLowerCase();
    const numCacheNodes = properties?.NumCacheNodes;

    if (engine === 'redis' && (!numCacheNodes || numCacheNodes === 1)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Use AWS::ElastiCache::ReplicationGroup with AutomaticFailoverEnabled: true instead of single-node CacheCluster for multi-AZ deployment.`
      );
    }

    return null;
  }
}

export default new Elasticache001Rule();