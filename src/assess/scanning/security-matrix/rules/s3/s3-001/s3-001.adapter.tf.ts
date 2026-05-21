import { AdapterFactory, TfContext, TerraformResource } from '../../../controls/types.js';
import { S3001Adapter } from './s3-001.adapter.js';

export class S3001TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_s3_bucket', 'aws_s3_bucket_logging'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): S3001TfAdapter {
    return new S3001TfAdapter(context);
  }
}

class S3001TfAdapter implements S3001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasServerAccessLogging(): boolean {
    if (this.hasInlineLogging()) return true;
    return this.hasExternalLoggingResource();
  }

  isLogDestination(): boolean {
    const bucketName = this.getBucketName();
    if (!bucketName) return false;
    return this.ctx.allResources.some(resource => this.referencesAsLogTarget(resource, bucketName));
  }

  private hasInlineLogging(): boolean {
    const values = this.getValues(this.ctx.resource);
    const logging = values?.logging;
    return Array.isArray(logging) ? logging.length > 0 : this.isNonEmptyObject(logging);
  }

  private hasExternalLoggingResource(): boolean {
    const bucketName = this.getBucketName();
    if (!bucketName) return false;
    return this.ctx.allResources.some(resource => this.isLoggingResourceFor(resource, bucketName));
  }

  private isLoggingResourceFor(resource: TerraformResource, bucketName: string): boolean {
    if (resource.type !== 'aws_s3_bucket_logging') return false;
    const values = this.getValues(resource);
    return values?.bucket === bucketName;
  }

  private referencesAsLogTarget(resource: TerraformResource, bucketName: string): boolean {
    if (resource.type !== 'aws_s3_bucket_logging') return false;
    const values = this.getValues(resource);
    return values?.target_bucket === bucketName;
  }

  private getBucketName(): string | undefined {
    const values = this.getValues(this.ctx.resource);
    const bucket = values?.bucket;
    return typeof bucket === 'string' ? bucket : undefined;
  }

  private getValues(resource: TerraformResource): Record<string, unknown> | undefined {
    return (resource as unknown as { values?: Record<string, unknown> }).values;
  }

  private isNonEmptyObject(value: unknown): boolean {
    return typeof value === 'object' && value !== null && Object.keys(value as object).length > 0;
  }
}
