import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfElasticache002Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ELASTICACHE-002',
      'HIGH',
      'ElastiCache Redis cluster not configured with Redis AUTH authentication',
      ['aws_elasticache_replication_group', 'aws_elasticache_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (!this.isRedisEngine(resource)) {
      return null;
    }

    if (resource.type === 'aws_elasticache_replication_group') {
      return this.evaluateReplicationGroup(resource, projectName);
    }

    if (resource.type === 'aws_elasticache_cluster') {
      return this.evaluateCacheCluster(resource, projectName);
    }

    return null;
  }

  private isRedisEngine(resource: TerraformResource): boolean {
    if (resource.type === 'aws_elasticache_replication_group') {
      return true;
    }
    const engine = resource.values?.engine;
    return engine === 'redis';
  }

  private evaluateReplicationGroup(resource: TerraformResource, projectName: string): ScanResult | null {
    const authToken = resource.values?.auth_token;
    const transitEncryption = resource.values?.transit_encryption_enabled;

    const hasAuthToken = authToken !== undefined && authToken !== null && authToken !== '';
    const hasTransitEncryption = transitEncryption === true;

    if (!hasAuthToken || !hasTransitEncryption) {
      const issues: string[] = [];
      if (!hasAuthToken) {
        issues.push('Set auth_token to enable Redis AUTH authentication');
      }
      if (!hasTransitEncryption) {
        issues.push('Set transit_encryption_enabled to true (required for auth_token)');
      }
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `${issues.join('. ')}. Use AWS Secrets Manager to store the auth token securely.`
      );
    }

    return null;
  }

  private evaluateCacheCluster(resource: TerraformResource, projectName: string): ScanResult | null {
    return this.createScanResult(
      resource,
      projectName,
      this.description,
      `aws_elasticache_cluster does not support Redis AUTH. Use aws_elasticache_replication_group with auth_token and transit_encryption_enabled instead.`
    );
  }
}

export default new TfElasticache002Rule();
