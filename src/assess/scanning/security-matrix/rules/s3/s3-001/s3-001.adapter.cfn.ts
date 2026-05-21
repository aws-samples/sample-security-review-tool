import { AdapterFactory, CfnContext, Resource, Template } from '../../../controls/types.js';
import { S3001Adapter } from './s3-001.adapter.js';

const UNRESOLVED_INTRINSIC_KEYS = ['Fn::If', 'Fn::ImportValue'];

export class S3001CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::S3::Bucket'];

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

  hasServerAccessLogging(): boolean {
    const properties = this.ctx.resource.Properties as Record<string, unknown> | undefined;
    const loggingConfiguration = properties?.LoggingConfiguration;
    if (this.hasUnresolvedIntrinsic(loggingConfiguration)) return true;
    return this.isNonEmptyObject(loggingConfiguration);
  }

  isLogDestination(): boolean {
    const buckets = this.collectOtherBuckets();
    return buckets.some(bucket => this.bucketMayLogTo(bucket, this.resourceId));
  }

  private collectOtherBuckets(): Resource[] {
    const resources = (this.ctx.template as Template).Resources ?? {};
    const otherBuckets: Resource[] = [];
    for (const [logicalId, resource] of Object.entries(resources)) {
      if (logicalId === this.resourceId) continue;
      if (resource.Type === 'AWS::S3::Bucket') otherBuckets.push(resource);
    }
    return otherBuckets;
  }

  private bucketMayLogTo(bucket: Resource, targetLogicalId: string): boolean {
    const properties = bucket.Properties as Record<string, unknown> | undefined;
    const loggingConfiguration = properties?.LoggingConfiguration;
    if (!loggingConfiguration) return false;
    if (this.hasUnresolvedIntrinsic(loggingConfiguration)) return true;
    const destination = (loggingConfiguration as Record<string, unknown>).DestinationBucketName;
    return destination === targetLogicalId;
  }

  private hasUnresolvedIntrinsic(value: unknown): boolean {
    if (typeof value !== 'object' || value === null) return false;
    return UNRESOLVED_INTRINSIC_KEYS.some(key => key in (value as object));
  }

  private isNonEmptyObject(value: unknown): boolean {
    return typeof value === 'object' && value !== null && Object.keys(value as object).length > 0;
  }
}
