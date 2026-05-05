import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfElasticache001Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ELASTICACHE-001',
      'HIGH',
      'ElastiCache Redis cluster not configured for multi-AZ deployment',
      ['aws_elasticache_replication_group', 'aws_elasticache_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_elasticache_replication_group') {
      return this.evaluateReplicationGroup(resource, projectName);
    }

    if (resource.type === 'aws_elasticache_cluster') {
      return this.evaluateCacheCluster(resource, projectName);
    }

    return null;
  }

  private evaluateReplicationGroup(resource: TerraformResource, projectName: string): ScanResult | null {
    const automaticFailover = resource.values?.automatic_failover_enabled;
    const numCacheClusters = resource.values?.num_cache_clusters;
    const numNodeGroups = resource.values?.num_node_groups;

    const hasMultiAZ = automaticFailover === true ||
      (numCacheClusters && numCacheClusters > 1) ||
      (numNodeGroups && numNodeGroups > 1);

    if (!hasMultiAZ) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set automatic_failover_enabled to true and ensure num_cache_clusters > 1 for multi-AZ deployment.`
      );
    }

    return null;
  }

  private evaluateCacheCluster(resource: TerraformResource, projectName: string): ScanResult | null {
    const engine = resource.values?.engine;
    const numCacheNodes = resource.values?.num_cache_nodes;

    if (engine === 'redis' && (!numCacheNodes || numCacheNodes === 1)) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Use aws_elasticache_replication_group with automatic_failover_enabled = true instead of a single-node cluster for multi-AZ deployment.`
      );
    }

    return null;
  }
}

export default new TfElasticache001Rule();
