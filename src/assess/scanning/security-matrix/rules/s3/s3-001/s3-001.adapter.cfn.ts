import { AdapterFactory, CfnContext, Resource, Template } from '../../../controls/types.js';
import { S3001Adapter } from './s3-001.adapter.js';

const S3_BUCKET_TYPE = 'AWS::S3::Bucket';
const UNRESOLVED_INTRINSIC_KEYS = ['Fn::If', 'Fn::ImportValue'];

export class S3001CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = [S3_BUCKET_TYPE];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): S3001CfnAdapter {
    return new S3001CfnAdapter(context);
  }
}

class S3001CfnAdapter implements S3001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  hasLoggingConfigured(): boolean {
    const properties = this.getProperties(this.ctx.resource);
    const loggingConfig = properties['LoggingConfiguration'];
    if (!this.isPlainObject(loggingConfig)) return false;
    return this.configuresLogDelivery(loggingConfig);
  }

  isLogDestination(): boolean {
    const buckets = this.collectOtherBuckets(this.ctx.template);
    return buckets.some(bucket => this.bucketTargetsThis(bucket));
  }

  /**
   * A conditional block is only unknowable if one of its branches would actually
   * deliver logs — `{Fn::If: [C, {DestinationBucketName: ...}, {Ref: AWS::NoValue}]}`
   * may or may not log, so it passes. When no branch names a destination, logging
   * is off however the condition resolves, and the bucket must still be flagged.
   */
  private configuresLogDelivery(loggingConfig: unknown): boolean {
    if (!this.isPlainObject(loggingConfig)) return false;
    const branches = this.conditionalBranches(loggingConfig);
    if (branches) return branches.some(branch => this.configuresLogDelivery(branch));
    if (this.isUnresolvedIntrinsic(loggingConfig)) return true;
    return this.hasDestinationBucket(loggingConfig as Record<string, unknown>);
  }

  private conditionalBranches(value: unknown): unknown[] | undefined {
    const branches = (value as Record<string, unknown>)['Fn::If'];
    return Array.isArray(branches) ? branches.slice(1) : undefined;
  }

  private hasDestinationBucket(loggingConfig: Record<string, unknown>): boolean {
    const destination = loggingConfig['DestinationBucketName'];
    if (typeof destination === 'string' && destination.length > 0) return true;
    // If the destination is itself an unresolvable intrinsic, treat as configured.
    return this.isUnresolvedIntrinsic(destination);
  }

  private collectOtherBuckets(template: Template): Resource[] {
    const resources = template.Resources ?? {};
    const result: Resource[] = [];
    for (const [logicalId, resource] of Object.entries(resources)) {
      if (logicalId === this.ctx.logicalId) continue;
      if (resource.Type === S3_BUCKET_TYPE) result.push(resource);
    }
    return result;
  }

  /**
   * The exemption requires an explicit destination reference (REQ-05), so only the
   * DestinationBucketName of each candidate branch is compared. Matching anywhere in
   * the block would let an unrelated value such as a LogFilePrefix exempt a bucket.
   */
  private bucketTargetsThis(bucket: Resource): boolean {
    const properties = this.getProperties(bucket);
    return this.destinationsOf(properties['LoggingConfiguration']).some(destination =>
      this.referencesThisBucket(destination)
    );
  }

  private destinationsOf(loggingConfig: unknown): unknown[] {
    if (!this.isPlainObject(loggingConfig)) return [];
    const branches = this.conditionalBranches(loggingConfig);
    if (branches) return branches.flatMap(branch => this.destinationsOf(branch));
    return [(loggingConfig as Record<string, unknown>)['DestinationBucketName']];
  }

  private isUnresolvedIntrinsic(value: unknown): boolean {
    if (!this.isPlainObject(value)) return false;
    const keys = Object.keys(value as Record<string, unknown>);
    return keys.some(k => UNRESOLVED_INTRINSIC_KEYS.includes(k));
  }

  private referencesThisBucket(value: unknown): boolean {
    if (typeof value === 'string') return value === this.ctx.logicalId;
    if (Array.isArray(value)) return value.some(v => this.referencesThisBucket(v));
    if (this.isPlainObject(value)) {
      return Object.values(value as Record<string, unknown>).some(v => this.referencesThisBucket(v));
    }
    return false;
  }

  private getProperties(resource: Resource): Record<string, unknown> {
    const properties = (resource as { Properties?: unknown }).Properties;
    return this.isPlainObject(properties) ? (properties as Record<string, unknown>) : {};
  }

  private isPlainObject(value: unknown): boolean {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }
}
