import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Elasticache002Rule extends BaseRule {
  constructor() {
    super(
      'ELASTICACHE-002',
      'HIGH',
      'ElastiCache Redis cluster not configured with Redis AUTH authentication',
      ['AWS::ElastiCache::ReplicationGroup', 'AWS::ElastiCache::CacheCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const resourceType = resource.Type;
    const properties = resource.Properties;

    // Only check Redis clusters, skip Memcached
    if (!this.isRedisEngine(properties)) {
      return null;
    }

    if (resourceType === 'AWS::ElastiCache::ReplicationGroup') {
      return this.evaluateReplicationGroup(resource, stackName);
    } else if (resourceType === 'AWS::ElastiCache::CacheCluster') {
      return this.evaluateCacheCluster(resource, stackName);
    }

    return null;
  }

  private isRedisEngine(properties: any): boolean {
    const engine = properties?.Engine?.toLowerCase();

    // If no engine specified, default is Memcached, so we skip
    if (!engine) {
      return false;
    }

    return engine === 'redis';
  }

  private evaluateReplicationGroup(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const properties = resource.Properties;

    const authToken = properties?.AuthToken;
    const transitEncryption = properties?.TransitEncryptionEnabled;

    // Check for various ways AuthToken might be configured
    const hasAuthToken = this.hasAuthTokenConfigured(authToken);
    const hasTransitEncryption = transitEncryption === true;

    if (!hasAuthToken || !hasTransitEncryption) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        this.generateReplicationGroupFix(hasAuthToken, hasTransitEncryption)
      );
    }

    return null;
  }

  private hasAuthTokenConfigured(authToken: any): boolean {
    if (!authToken) {
      return false;
    }

    // Check for various CloudFormation token formats
    if (typeof authToken === 'string' && authToken.trim().length > 0) {
      return true;
    }

    // Check for CloudFormation references/functions
    if (typeof authToken === 'object' && authToken !== null) {
      // Could be !Ref, !Sub, !GetAtt, etc.
      return Object.keys(authToken).length > 0;
    }

    return false;
  }

  private generateReplicationGroupFix(hasAuthToken: boolean, hasTransitEncryption: boolean): string {
    let message = ``;
    const issues = [];

    if (!hasAuthToken) {
      issues.push("Set AuthToken property to enable Redis AUTH authentication");
    }

    if (!hasTransitEncryption) {
      issues.push("Set TransitEncryptionEnabled to true (required for AuthToken)");
    }

    message += issues.join(". ") + ". ";
    message += "Use AWS Secrets Manager to store the auth token securely.";

    return message;
  }

  private evaluateCacheCluster(resource: CloudFormationResource, stackName: string): ScanResult | null {
    // CacheCluster doesn't support AuthToken for Redis
    return this.createScanResult(
      resource,
      stackName,
      `${this.description}`,
      `AWS::ElastiCache::CacheCluster does not support Redis AUTH. Use AWS::ElastiCache::ReplicationGroup with AuthToken and TransitEncryptionEnabled properties instead for secure Redis authentication.`
    );
  }
}

export default new Elasticache002Rule();