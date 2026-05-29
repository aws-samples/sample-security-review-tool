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
    // When the logging configuration is governed by an unresolvable intrinsic
    // (Fn::If, Fn::ImportValue), we cannot determine compliance and must
    // treat it as "configured" so the control passes.
    if (this.isUnresolvedIntrinsic(loggingConfig)) return true;
    return this.hasDestinationBucket(loggingConfig as Record<string, unknown>);
  }

  isLogDestination(): boolean {
    const buckets = this.collectOtherBuckets(this.ctx.template);
    return buckets.some(bucket => this.bucketTargetsThis(bucket));
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

  private bucketTargetsThis(bucket: Resource): boolean {
    const properties = this.getProperties(bucket);
    const loggingConfig = properties['LoggingConfiguration'];
    if (!this.isPlainObject(loggingConfig)) return false;
    if (this.isUnresolvedIntrinsic(loggingConfig)) {
      return this.referencesThisBucket(loggingConfig);
    }
    const destination = (loggingConfig as Record<string, unknown>)['DestinationBucketName'];
    return typeof destination === 'string' && destination === this.ctx.logicalId;
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
